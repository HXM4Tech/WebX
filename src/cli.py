#!/usr/bin/env python3

import os
import sys
import socket
import pwd
import ipaddress

def readline_completer(text, state):
    options = ["exit", "help", "stats", "known-peers", "wallet-info"]

    for option in options:
        if option.startswith(text):
            if not state:
                return option
            else:
                state -= 1

def execute_command(sock, cmd):
    if cmd == "":
        return
    elif cmd == "exit":
        print("\nGoodbye!")
        sys.exit(0)
    elif cmd == "help":
        print("Commands: exit, help, stats, known-peers, wallet-info")
    elif cmd == "stats":
        sock.send(b"\x00")

        msg_type = sock.recv(1)
        assert msg_type == b"\x01", "Invalid response"

        total_packets_sent = int.from_bytes(sock.recv(16), "big")
        total_packets_received = int.from_bytes(sock.recv(16), "big")
        total_packets_forwarded = int.from_bytes(sock.recv(16), "big")

        print()
        print("+" + "-" * 25 + "+" + "-" * 25 + "+")
        print(f"| Total packets sent      | {total_packets_sent:<23} |")
        print(f"| Total packets received  | {total_packets_received:<23} |")
        print(f"| Total packets forwarded | {total_packets_forwarded:<23} |")
        print("+" + "-" * 25 + "+" + "-" * 25 + "+")
        print()
    elif cmd == "known-peers":
        sock.send(b"\x02")

        msg_type = sock.recv(1)
        assert msg_type == b"\x03", "Invalid response"

        d = {}
        items = int.from_bytes(sock.recv(2), "big")

        for _ in range(items):
            ipv6_addr = int.from_bytes(sock.recv(16), "big")
            depth_in_tree = int.from_bytes(sock.recv(1), "big")

            d[ipv6_addr] = depth_in_tree
        
        print()
        print("+" + "-" * 57 + "+")
        print(f"| {'WebX IPv6 address':^39} | Depth in tree |")
        print("+" + "-" * 41 + "+" + "-" * 15 + "+")

        for ipv6_addr, depth_in_tree in d.items():
            print(f"| {str(ipaddress.IPv6Address(ipv6_addr)):<39} | {depth_in_tree:<13} |")
        
        print("+" + "-" * 57 + "+")
        print()
    elif cmd == "wallet-info":
        sock.send(b"\x04")

        msg_type = sock.recv(1)
        assert msg_type == b"\x05", "Invalid response"

        public_key = sock.recv(33)
        ipv6_addr = int.from_bytes(sock.recv(16), "big")

        print()
        print("+" + "-" * 19 + "+" + "-" * 68 + "+")
        print(f"| Public key        | {public_key.hex():<66} |")
        print(f"| WebX IPv6 address | {str(ipaddress.IPv6Address(ipv6_addr)):<66} |")
        print("+" + "-" * 19 + "+" + "-" * 68 + "+")
        print()
    else:
        print(f"{cmd}: command not found", file=sys.stderr)
        print('Type "help" for a list of commands', file=sys.stderr)

def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    if os.getuid() == 0:
        running_ids = [int(x.split("-")[1].split(".")[0]) for x in os.listdir("/tmp") if x.startswith("webx-") and x.endswith(".sock")]

        # If there are multiple instances, give the user a choice
        if len(running_ids) > 1:
            print("Multiple instances of WebX are running. Please select one.")
            print()

            for i in range(len(running_ids)):
                print(f"{i + 1}. WebX daemon running as user {pwd.getpwuid(running_ids[i]).pw_name}")

            print()

            while True:
                try:
                    choice = int(input("Choice> ").strip())
                except ValueError:
                    print("Invalid choice.", file=sys.stderr)
                    continue

                if choice < 1 or choice > len(running_ids):
                    print("Invalid choice.", file=sys.stderr)
                    continue
                else:
                    break

            sock.connect(f"/tmp/webx-{running_ids[choice - 1]}.sock")
            print()
        else:
            if len(running_ids) == 0:
                print("WebX is not running", file=sys.stderr)
                sys.exit(1)

            sock.connect(f"/tmp/webx-{running_ids[0]}.sock")
    else:
        try:
            sock.connect(f"/tmp/webx-{os.getuid()}.sock")
        except Exception:
            print("WebX is not running or you are running the script as different user as WebX", file=sys.stderr)
            sys.exit(1)

    if len(sys.argv) > 1:
        execute_command(sock, " ".join(sys.argv[1:]))
        sys.exit(0)

    try:
        import readline
        readline.parse_and_bind("tab: complete")
        readline.set_completer(readline_completer)
    except ImportError:
        pass

    while True:
        cmd = input("WebX CLI> ").strip()
        execute_command(sock, cmd)

 

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[SIGINT] Goodbye!")
    except EOFError:
        print("\n\n[EOF] Goodbye!")
    except BrokenPipeError:
        print()
        print("WebX process exited! Cannot operate.", file=sys.stderr)
