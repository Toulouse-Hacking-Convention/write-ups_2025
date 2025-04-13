In this challenge, the real transmission is hidden nowhere in the packets, but rather in their number.
The communication happened using morse code, adapted for this use.

## Clues :

The content of the TCP stream is a paragraph from the Dutch wikipedia page of an animal, the walrus. While really cute, the walrus is named in french as morse. This aims to lead the player on the track of a morse code.

Get tcp data in ascii : `tshark -r file.pcap -Y "tcp" -T fields -e tcp.stream | sort -n | uniq | while read stream; do     echo "=== TCP Stream $stream ===";     tshark -r file.pcap -Y "tcp.stream==$stream" -T fields -e data | xxd -r -p;     echo -e "\n"; done`

The content of the UDP packet is a paragraph from the traditional chinese wikipedia page of time. This aims to lead the player to think of those UDP packets as the wait between morse symbols.
because of the utf-8 and not ascii symbols, this can confuse.

Get udp data in utf-8 : `tshark -r file.pcap -Y "udp" -T fields -e data | xxd -r -p | iconv -f utf-8 -t utf-8`

## Solve

Morse code can be simplified to 4 symbols. The `.` and `-`, but also the short wait between those last two and the longer wait between two letters.

I chose to represent the `.` by a TCP packet being sent. To represent the `-`, i then "extended" the dot by sending 3.
To represent the waiting periods between TCP packets, I chose UDP packets. Following the same logic, a short wait between two symbols is represented by a single UDP packet, whereas a long wait between two letters being sent is represented by 3 udp packets being sent.

TCP adds packets at the start of the communication, and ACK each packet received. This is not a problemin the communication.

Here is a script that extracts the flag from the transmission :

```python
from scapy.all import *

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

def count_consecutive_protocols(file_path):
    packets = rdpcap(file_path)

    counts = []
    if not packets:
        return counts

    # Determine the first protocol (useful in counts_to_morse)
    prev_proto = "TCP" if TCP in packets[0] else "UDP" if UDP in packets[0] else "Other"
    print("The first protocol is", prev_proto)
    count = 1

    for packet in packets[1:]:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "Other"

        if proto == prev_proto:
            count += 1
        else:
            counts.append(count)
            count = 1
            prev_proto = proto

    counts.append(count)
    return counts

def counts_to_morse(counts, first_protocol):
    letter = ""
    type = first_protocol
    for count in counts:
        if type == "TCP":
            if count >= 3:
                letter += "-"
            else:
                letter += "."
        else:
            if count >= 3:
                letter += " "
        type = "TCP" if type == "UDP" else "UDP"
    return letter

def morse_to_text(morse):
    text = ""
    for letter in morse.split(" "):
        for key, value in MORSE_CODE_DICT.items():
            if value == letter:
                text += key
                break
    return text


counts = count_consecutive_protocols("capture.pcap")
morse = counts_to_morse(counts, "TCP")
print(morse_to_text(morse))
```

