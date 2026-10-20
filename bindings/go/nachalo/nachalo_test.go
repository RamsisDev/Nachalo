package nachalo_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/RamsisDev/Nachalo/bindings/go/nachalo"
)

var (
	context = []byte("my-app v1")
	clock   = nachalo.Clock{Now: 0, NowUnix: 1_900_000_000}
	config  = nachalo.NewConfig(nachalo.ProfileInteractive)
)

const fixedWords = "alpha cable echo forest orbit velvet"

func must[T any](t *testing.T) func(T, error) T {
	return func(value T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

// handshake runs msg1 from invitationA, answered by invitationB: both sides before the safety
// words. It destroys everything else it made.
func handshake(t *testing.T, invitationA, invitationB *nachalo.Invitation) (*nachalo.Unconfirmed, *nachalo.Unconfirmed) {
	t.Helper()
	a := must[*nachalo.Initiator](t)(nachalo.InitiatorStart(invitationA, []byte("A's payload"), clock))
	defer a.Destroy()
	listener := nachalo.NewListener(invitationB)
	defer listener.Destroy()
	answer := must[nachalo.Answer](t)(listener.Respond(a.Msg1(), []byte("B's payload"), clock))
	defer answer.Responder.Destroy()
	finished := must[nachalo.Finished](t)(a.Finish(answer.Msg2, clock))
	return finished.Unconfirmed, must[*nachalo.Unconfirmed](t)(answer.Responder.Finish(finished.Msg3, clock))
}

func TestLiveHandshake(t *testing.T) {
	words := must[string](t)(nachalo.Words(nachalo.WordCount()))
	invitation := must[*nachalo.Invitation](t)(nachalo.InvitationLive(words, context, config))
	defer invitation.Destroy()
	if uint32(len(invitation.Rendezvous())) != nachalo.RendezvousLen() {
		t.Fatal("rendezvous length")
	}

	ua, ub := handshake(t, invitation, invitation)
	defer ua.Destroy()
	defer ub.Destroy()
	if ua.Role() != nachalo.RoleInitiator || ub.Role() != nachalo.RoleResponder {
		t.Fatal("roles")
	}
	a := must[*nachalo.Established](t)(ua.Verify(must[string](t)(ub.SafetyWords()), clock))
	defer a.Destroy()
	b := must[*nachalo.Established](t)(ub.Confirm(clock))
	defer b.Destroy()
	if !bytes.Equal(a.Key(), b.Key()) || !bytes.Equal(a.Transcript(), b.Transcript()) ||
		!bytes.Equal(a.Export([]byte("x")), b.Export([]byte("x"))) {
		t.Fatal("the two sides differ")
	}
	if !bytes.Equal(a.PeerPayload(), []byte("B's payload")) || !bytes.Equal(b.PeerPayload(), []byte("A's payload")) {
		t.Fatal("payloads")
	}
	// Confirm consumed ub.
	_, err := ub.Confirm(clock)
	wantErr(t, err, nachalo.ErrNachaloErrorExpired)
	_, err = ub.SafetyWords()
	wantErr(t, err, nachalo.ErrNachaloErrorExpired)
}

func TestWrongWordsRejected(t *testing.T) {
	invitation := must[*nachalo.Invitation](t)(nachalo.InvitationLive(fixedWords, context, config))
	defer invitation.Destroy()
	wrong := must[*nachalo.Invitation](t)(nachalo.InvitationLive("alpha cable echo forest orbit zoo", context, config))
	defer wrong.Destroy()
	a := must[*nachalo.Initiator](t)(nachalo.InitiatorStart(invitation, []byte("A"), clock))
	defer a.Destroy()

	guess := must[nachalo.Answer](t)(nachalo.NewListener(wrong).Respond(a.Msg1(), []byte("M"), clock))
	defer guess.Destroy()
	_, err := a.Finish(guess.Msg2, clock)
	wantErr(t, err, nachalo.ErrNachaloErrorRejected)
	var typed *nachalo.NachaloErrorRejected
	if !errors.As(err, &typed) {
		t.Fatalf("errors.As: %v", err)
	}

	// The bogus answer left A usable.
	answer := must[nachalo.Answer](t)(nachalo.NewListener(invitation).Respond(a.Msg1(), []byte("B"), clock))
	defer answer.Destroy()
	finished := must[nachalo.Finished](t)(a.Finish(answer.Msg2, clock))
	finished.Destroy()
	_, err = a.Finish(answer.Msg2, clock)
	wantErr(t, err, nachalo.ErrNachaloErrorExpired)

	_, err = nachalo.InvitationLive("alpha cable", context, config)
	wantErr(t, err, nachalo.ErrNachaloErrorBadWords)
}

func TestManInTheMiddleShowsDifferentSafetyWords(t *testing.T) {
	invitation := must[*nachalo.Invitation](t)(nachalo.InvitationLive(fixedWords, context, config))
	defer invitation.Destroy()
	// M answers A as B, and invites B as A, with the same words.
	a, mWithA := handshake(t, invitation, invitation)
	mWithB, b := handshake(t, invitation, invitation)
	for _, side := range []*nachalo.Unconfirmed{a, b, mWithA, mWithB} {
		defer side.Destroy()
	}
	words := func(u *nachalo.Unconfirmed) string { return must[string](t)(u.SafetyWords()) }
	if words(a) != words(mWithA) || words(b) != words(mWithB) || words(a) == words(b) {
		t.Fatal("safety words")
	}
	_, err := a.Verify(words(b), clock)
	wantErr(t, err, nachalo.ErrNachaloErrorRejected)
}

func TestAppointmentAndPhysicalToken(t *testing.T) {
	at := clock.NowUnix
	wordsA := must[string](t)(nachalo.Words(nachalo.AppointmentWordsA()))
	wordsB := must[string](t)(nachalo.Words(nachalo.AppointmentWordsB()))
	token := must[[]byte](t)(nachalo.NewPhysicalToken(3600, at))
	words := must[string](t)(nachalo.Words(nachalo.WordCount()))
	for _, build := range []func() (*nachalo.Invitation, error){
		func() (*nachalo.Invitation, error) {
			return nachalo.InvitationAppointment(wordsA, wordsB, at, context, at, config)
		},
		func() (*nachalo.Invitation, error) {
			return nachalo.InvitationPhysicalToken(words, token, context, at, config)
		},
	} {
		a := must[*nachalo.Invitation](t)(build())
		b := must[*nachalo.Invitation](t)(build())
		if !bytes.Equal(a.Rendezvous(), b.Rendezvous()) {
			t.Fatal("rendezvous")
		}
		ua, ub := handshake(t, a, b)
		must[*nachalo.Established](t)(ua.Verify(must[string](t)(ub.SafetyWords()), clock)).Destroy()
		for _, object := range []interface{ Destroy() }{ua, ub, a, b} {
			object.Destroy()
		}
	}
	_, err := nachalo.InvitationPhysicalToken(words, token[1:], context, at, config)
	wantErr(t, err, nachalo.ErrNachaloErrorRejected)
	_, err = nachalo.InvitationAppointment(wordsA, wordsB, at+7200, context, at, config)
	wantErr(t, err, nachalo.ErrNachaloErrorExpired)
}
