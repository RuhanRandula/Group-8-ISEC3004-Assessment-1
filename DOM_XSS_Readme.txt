dom_xss_demo_vulnerable/app.py is CurtiBoard with the DOM XSS flaw.
dom_xss_demo/app.py is the mitigated version (same app, textContent + CSP).
exploit/dom_xss_exploit.py prints the attack URLs; it does not run the attack itself.

To run the vulnerable version:
1. Install Flask:
   pip install -r dom_xss_demo/requirements.txt

2. Start the vulnerable server:
   cd dom_xss_demo_vulnerable
   python app.py

3. Print the attack URLs:
   python dom_xss_demo/exploit/dom_xss_exploit.py

4. Copy one of the printed URLs and paste it into your browser (while the server above is running).
   For Payload 2 (silent exfiltration), also run in a second terminal:
   python -m http.server 9999

To run the mitigated version instead:
   Stop the server above, then:
   cd dom_xss_demo
   python app.py
   Paste the same URLs - the payload now shows as plain text and no alert fires.
