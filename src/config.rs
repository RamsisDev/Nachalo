//! Local limits. Each device bounds only itself, and none of them travels on the wire or enters
//! CPace's channel identifier, so devices with different settings still complete a handshake.

use std::time::Duration;

use crate::handshake::{Error, PAYLOAD_CEILING};

/// A default and the range a [`Config`] may move it within.
#[derive(Clone, Copy, Debug)]
pub struct Bounded<T> {
    /// The smallest value allowed.
    pub min: T,
    /// The value a new [`Config`] starts with.
    pub default: T,
    /// The largest value allowed.
    pub max: T,
}

impl<T: Copy + PartialOrd> Bounded<T> {
    fn check(&self, value: T) -> Result<T, Error> {
        if self.min <= value && value <= self.max {
            Ok(value)
        } else {
            Err(Error::OutOfRange)
        }
    }
}

const fn minutes(min: u64, default: u64, max: u64) -> Bounded<Duration> {
    Bounded {
        min: Duration::from_secs(min * 60),
        default: Duration::from_secs(default * 60),
        max: Duration::from_secs(max * 60),
    }
}

/// A named set of defaults and allowed ranges for one kind of application. Profiles are local:
/// devices on different profiles interoperate.
#[derive(Debug)]
pub struct Profile {
    /// Identifies the profile, for instance in a saved [`Listener`](crate::Listener).
    pub name: &'static str,
    /// How long each pending step lives on this device.
    pub invite_ttl: Bounded<Duration>,
    /// Wrong msg2 this device takes as initiator, and msg1 it answers as responder, per
    /// invitation. Each one is an online guess at the words.
    pub max_answers: Bounded<u16>,
    /// Largest payload this device sends. Receivers accept up to [`PAYLOAD_CEILING`].
    pub max_payload: Bounded<usize>,
    /// How long after its start time this device builds and answers an appointment.
    pub appointment_window: Bounded<Duration>,
    /// A suggested lifetime for [`new_physical_token`](crate::new_physical_token). It has no
    /// upper bound: the token's secret cannot be guessed.
    pub default_token_lifetime: Duration,
}

impl Profile {
    /// Chat or call, both online. Its defaults are the fixed values of earlier drafts.
    pub const INTERACTIVE: Profile = Profile {
        name: "interactive",
        invite_ttl: minutes(2, 10, 30),
        max_answers: Bounded {
            min: 8,
            default: 64,
            max: 128,
        },
        max_payload: Bounded {
            min: 0,
            default: 1024,
            max: 2048,
        },
        appointment_window: minutes(5, 30, 120),
        default_token_lifetime: Duration::from_secs(24 * 3600),
    };

    /// The first key of a post-quantum ratchet plus an identity, such as ML-KEM-1024 and
    /// ML-DSA-65 public keys and a signature.
    pub const PQ_MESSENGER: Profile = Profile {
        name: "pq-messenger",
        max_payload: Bounded {
            min: 0,
            default: 4096,
            max: PAYLOAD_CEILING,
        },
        ..Self::INTERACTIVE
    };

    /// QR, Bluetooth or LAN, side by side. Appointments keep the window of
    /// [`INTERACTIVE`](Profile::INTERACTIVE).
    pub const NEARBY: Profile = Profile {
        name: "nearby",
        invite_ttl: Bounded {
            min: Duration::from_secs(30),
            default: Duration::from_secs(120),
            max: Duration::from_secs(300),
        },
        max_answers: Bounded {
            min: 1,
            default: 4,
            max: 16,
        },
        max_payload: Bounded {
            min: 0,
            default: 1024,
            max: PAYLOAD_CEILING,
        },
        ..Self::INTERACTIVE
    };
}

/// This device's limits: a [`Profile`] and the values chosen within its ranges.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    profile: &'static Profile,
    pub(crate) invite_ttl: Duration,
    pub(crate) max_answers: u16,
    pub(crate) max_payload: usize,
    pub(crate) appointment_window: Duration,
}

impl Config {
    /// Every value at the profile's default.
    pub const fn new(profile: &'static Profile) -> Self {
        Config {
            profile,
            invite_ttl: profile.invite_ttl.default,
            max_answers: profile.max_answers.default,
            max_payload: profile.max_payload.default,
            appointment_window: profile.appointment_window.default,
        }
    }

    /// The profile these values were chosen from.
    pub fn profile(&self) -> &'static Profile {
        self.profile
    }

    /// How long each pending step lives; [`Error::OutOfRange`] outside the profile's range.
    pub fn with_invite_ttl(self, ttl: Duration) -> Result<Self, Error> {
        let invite_ttl = self.profile.invite_ttl.check(ttl)?;
        Ok(Config { invite_ttl, ..self })
    }

    /// Wrong msg2 taken as initiator, and msg1 answered as responder, per invitation;
    /// [`Error::OutOfRange`] outside the profile's range.
    pub fn with_max_answers(self, answers: u16) -> Result<Self, Error> {
        let max_answers = self.profile.max_answers.check(answers)?;
        Ok(Config {
            max_answers,
            ..self
        })
    }

    /// Largest payload this device sends; [`Error::OutOfRange`] outside the profile's range.
    pub fn with_max_payload(self, bytes: usize) -> Result<Self, Error> {
        let max_payload = self.profile.max_payload.check(bytes)?;
        Ok(Config {
            max_payload,
            ..self
        })
    }

    /// How long after its start time an appointment works; [`Error::OutOfRange`] outside the
    /// profile's range.
    pub fn with_appointment_window(self, window: Duration) -> Result<Self, Error> {
        let appointment_window = self.profile.appointment_window.check(window)?;
        Ok(Config {
            appointment_window,
            ..self
        })
    }

    /// The config of a saved [`Listener`](crate::Listener): a built-in profile by name, and each
    /// value checked against its range again.
    pub(crate) fn restore(
        name: &[u8],
        invite_ttl: u64,
        max_answers: u16,
        max_payload: u64,
        appointment_window: u64,
    ) -> Result<Self, Error> {
        let profile = [
            &Profile::INTERACTIVE,
            &Profile::PQ_MESSENGER,
            &Profile::NEARBY,
        ]
        .into_iter()
        .find(|p| p.name.as_bytes() == name)
        .ok_or(Error::OutOfRange)?;
        Config::new(profile)
            .with_invite_ttl(Duration::from_secs(invite_ttl))?
            .with_max_answers(max_answers)?
            .with_max_payload(usize::try_from(max_payload).map_err(|_| Error::OutOfRange)?)?
            .with_appointment_window(Duration::from_secs(appointment_window))
    }

    /// log2 of the per-side guessing bound in live mode, rounded up: -36 by default.
    pub fn guess_bound_log2(&self) -> i32 {
        // The live rendezvous id leaves 42 of the words' 66 bits to guess.
        self.max_answers.next_power_of_two().ilog2() as i32 - 42
    }
}

impl Default for Config {
    fn default() -> Self {
        Config::new(&Profile::INTERACTIVE)
    }
}
