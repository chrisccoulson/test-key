package main

import (
	"fmt"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/snapcore/secboot"

	"golang.org/x/xerrors"
)

func dumpSrkInfo() error {
	tcti, err := tpm2.OpenTPMDevice("/dev/tpm0")
	if err != nil {
		return xerrors.Errorf("cannot open TPM: %w", err)
	}
	tpm, _ := tpm2.NewTPMContext(tcti)
	defer tpm.Close()

	srk, err := tpm.CreateResourceContextFromTPM(0x81000001)
	if err != nil {
		return xerrors.Errorf("cannot obtain context for SRK: %w", err)
	}

	fmt.Printf("SRK name: %x\n", srk.Name())

	tmpl, err := tpm.CreateResourceContextFromTPM(0x01810001)
	switch {
	case tpm2.IsResourceUnavailableError(err, 0x01810001):
		fmt.Println("No custom template was suppled to create the SRK")
	case err != nil:
		return xerrors.Errorf("cannot obtain context for SRK custom template: %w", err)
	default:
		pub, _, err := tpm.NVReadPublic(tmpl)
		if err != nil {
			return xerrors.Errorf("cannot read public area of SRK custom template: %w", err)
		}
		data, err := tpm.NVRead(tpm.OwnerHandleContext(), tmpl, pub.Size, 0, nil)
		if err != nil {
			return xerrors.Errorf("cannot read SRK custom template: %w", err)
		}
		fmt.Printf("SRK custom template: %x\n", data)
	}

	return nil
}

func run(args []string) error {
	if err := dumpSrkInfo(); err != nil {
		return xerrors.Errorf("cannot dump SRK info: %w", err)
	}

	if len(args) == 0 {
		return nil
	}

	tpm, err := secboot.ConnectToDefaultTPM()
	if err != nil {
		return xerrors.Errorf("cannot open TPM connection: %w", err)
	}
	defer tpm.Close()

	skoPath := args[0]

	sko, err := secboot.ReadSealedKeyObject(skoPath)
	if err != nil {
		return xerrors.Errorf("cannot read sealed key object: %w", err)
	}

	_, _, err = sko.UnsealFromTPM(tpm, "")
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
