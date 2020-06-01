# ModestSanitizer
REASONABLY SECURE GENERAL PURPOSE C# LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.
For output encoding see Anti-XSS.
For LDAP encoding see Anti-XSS.

DISCLAIMER: This library is opinionated in favor of en-US culture and ASCII-compatible characters. Support for international unicode character cleansing is out-of-scope for me at the moment.

ADVICE: Validate all input
RE-STATED: Developers often don't validate all input. 
They take the shotgun parser approach where they assume input is well-formed, whereas a recognizer would verify input as well-formed.
LANGSEC-Language-theoretic Security: treat all valid or expected inputs as a formal language and the input-handling routines as a recognizer for that language.

But I see this as two steps: 1. Sanitization (using a Recognizer) and 2. Input Validation.

EXAMPLE: 
1. If converting a string to an Integer, I want to sanitize it to only accept a valid minimum of -2147483648 with a valid maximum of 2147483647.
2. Then I may want to perform input validation because let's say in my application the valid values happen to be only from 0 to 1000.

It may be worth separating these out because we may want to monitor anomalous (potentially malicious) activity vs. expected common validation errors.
With expected validation errors we also typically want to report back to a user. Whereas with anomalous data we may just wish to log and alert security.

```
Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);

String potentiallyMaliciousString = "äiti®";
String stringLimitedToLetterlikeChars = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString);

//Removes the accent from the 'a', but removes the copyright symbol altogether
Assert.AreEqual("aiti", stringLimitedToLetterlikeChars); 

//ready for comparison against a whitelist!
```

Also, see below for an example of a whitelisting failure. 

A whitelist of applications by name somewhat works by limiting users to run only valid programs (such as installutil.exe) but since installutil.exe may be tricked into running another executable, the whitelist has been effectively bypassed. Try to look for such loopholes in your own whitelisting efforts?

SOURCE: https://attackiq.com/blog/2018/05/21/application-whitelist-bypass/