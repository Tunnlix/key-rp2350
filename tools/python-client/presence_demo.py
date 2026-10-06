"""Interactive python-fido2 selection against simulated C user presence.

Run: .venv/Scripts/python.exe tools/python-client/presence_demo.py
Enter confirms a fresh touch, d denies, c sends real CTAPHID_CANCEL.
Add --reset to reset the peer's PC vault within its power-on window.
"""

from threading import Event
import argparse
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2

from build_harness import build_harness
from fido2_harness import open_harness


def main():
    parser = argparse.ArgumentParser(description="Simulate user presence on the C test peer")
    parser.add_argument("--reset", action="store_true", help="Reset the peer's PC credential vault")
    parser.add_argument("--store-dir", help="Persistent PC vault directory; default is a private temporary vault")
    arguments = parser.parse_args()
    device = open_harness(build_harness(), storage_directory=arguments.store_dir)
    cancelled = Event()
    try:
        client = Ctap2(device)
        print("Waiting for user presence (30 seconds)." + (" Reset erases this PC vault's credentials and keys." if arguments.reset else ""))

        def prompt(status):
            if status != STATUS.UPNEEDED:
                return
            choice = input("Enter=touch, d=deny, c=cancel: ").strip().lower()
            if choice == "c":
                cancelled.set()
            elif choice == "d":
                device._connection.deny_presence()
            elif choice == "":
                device._connection.confirm_presence()
            else:
                print("No confirmation sent; the operation will time out.")

        if arguments.reset:
            client.reset(event=cancelled, on_keepalive=prompt)
            print("Confirmed; PC credential vault reset.")
            print(device._connection.storage_state())
        else:
            client.selection(event=cancelled, on_keepalive=prompt)
            print("Presence confirmed; authenticator selected.")
    except CtapError as error:
        print(f"Selection ended: {error}")
    except KeyboardInterrupt:
        print("Client interrupted.")
    finally:
        device.close()


if __name__ == "__main__":
    main()
