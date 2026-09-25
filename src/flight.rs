//! The requests in flight, one per address, so concurrent misses share one.
//!
//! A cache that checks, misses and then fetches lets every caller that misses in
//! the same moment fetch too: a middleware answering several requests from one
//! visitor at once paid for the same lookup several times. Every caller that
//! misses while a request for its address is in flight awaits that request
//! instead, whether a single lookup or a batch sent it, so the registry is ours
//! rather than the cache's: a batch has to know which addresses it leads before it
//! builds its chunks, and a coalescing `get_with` only tells a caller afterwards.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use futures_util::future::{FutureExt, Shared};
use tokio::sync::oneshot;

use crate::error::Error;
use crate::lookup::Lookup;

/// One address's request, as every caller awaiting it sees it land. It fails
/// only when the caller leading it was dropped first, and a waiter then tries
/// again rather than failing with it.
pub(crate) type Flight = Shared<oneshot::Receiver<Arc<Result<Lookup, Error>>>>;

#[derive(Debug, Default)]
pub(crate) struct Flights(Mutex<HashMap<String, Flight>>);

impl Flights {
    /// Joins the request in flight for each address that has one, and leads a new
    /// one for each that has none. The caller sends a request for every address
    /// the [`Pilot`] leads and lands each answer there.
    pub(crate) fn board<'a, 'b>(
        &'a self,
        ips: impl IntoIterator<Item = &'b str>,
    ) -> (Pilot<'a>, Vec<(String, Flight)>) {
        let mut flights = self.0.lock().expect("flights lock");
        let mut led = HashMap::new();
        let mut joined = Vec::new();
        for ip in ips {
            match flights.get(ip) {
                Some(flight) => joined.push((ip.to_owned(), flight.clone())),
                None => {
                    let (sender, receiver) = oneshot::channel();
                    flights.insert(ip.to_owned(), receiver.shared());
                    led.insert(ip.to_owned(), sender);
                }
            }
        }
        (Pilot { flights: self, led }, joined)
    }
}

/// The addresses one caller leads. Dropping it before an address lands, a
/// caller cancelled mid-request, takes that address off the board, so the next
/// caller leads a request of its own and every waiter tries again.
pub(crate) struct Pilot<'a> {
    flights: &'a Flights,
    led: HashMap<String, oneshot::Sender<Arc<Result<Lookup, Error>>>>,
}

impl Pilot<'_> {
    pub(crate) fn leads(&self, ip: &str) -> bool {
        self.led.contains_key(ip)
    }

    /// Hands every waiter the answer and takes the address off the board. Cache a
    /// served answer FIRST: a caller that missed the cache just before it landed
    /// finds no flight after this, and reads the cache again before it sends.
    pub(crate) fn land(&mut self, ip: &str, answer: &Result<Lookup, Error>) {
        if let Some(sender) = self.led.remove(ip) {
            self.flights.0.lock().expect("flights lock").remove(ip);
            let _ = sender.send(Arc::new(restate(answer)));
        }
    }
}

impl Drop for Pilot<'_> {
    fn drop(&mut self) {
        if self.led.is_empty() {
            return;
        }
        let mut flights = self.flights.0.lock().expect("flights lock");
        for ip in self.led.keys() {
            flights.remove(ip);
        }
    }
}

/// A landed answer as one waiter's own: the lookup cloned, an error restated
/// the way a batch restates a chunk's failure for each of its addresses.
pub(crate) fn restate(answer: &Result<Lookup, Error>) -> Result<Lookup, Error> {
    match answer {
        Ok(lookup) => Ok(lookup.clone()),
        Err(err) => Err(err.restated()),
    }
}
