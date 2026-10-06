"""Interactive python-fido2 selection against simulated C user presence.

Run: .venv/Scripts/python.exe tools/python-client/presence_demo.py
Enter confirms a fresh touch, d denies, c sends real CTAPHID_CANCEL.
"""

from threading import Event
from fido2.ctap import CtapError, STATUS
from fido2.ctap2 import Ctap2

from build_harness import build_harness
from fido2_harness import open_harness


def main():
    device = open_harness(build_harness())
    cancelled = Event()
    try:
        client = Ctap2(device)
        print("Waiting for user presence (30 seconds).")

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
