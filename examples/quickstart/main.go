// Command quickstart verifies one address against the live Bouncer API.
//
// It does nothing without -live: with it, it makes one billable call with the
// key in BOUNCER_API_KEY. Never run it in CI or tests.
//
//	BOUNCER_API_KEY=… go run ./examples/quickstart -live -email you@example.com
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mrz1836/go-bouncer"
)

func main() {
	live := flag.Bool("live", false, "make one billable call to the Bouncer API")
	email := flag.String("email", "avery.example@example.com", "the address to verify")
	flag.Parse()
	if !*live {
		fmt.Println("dry run: pass -live to make one billable call with BOUNCER_API_KEY")
		return
	}

	// The application chooses where the key comes from; the SDK reads no environment.
	client, err := bouncer.NewClient(os.Getenv("BOUNCER_API_KEY"))
	if err != nil {
		log.Fatal(err) // ErrInvalidConfig: no call was made
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// One billable call, whatever the result.
	v, err := client.Verify(ctx, bouncer.VerifyRequest{Email: *email})
	if err != nil {
		log.Fatal(err) // the check may already be billed: do not resend blindly
	}
	fmt.Println(v.Status, v.Reason)
}
