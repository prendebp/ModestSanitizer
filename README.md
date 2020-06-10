# ModestSanitizer
**REASONABLY SECURE GENERAL PURPOSE C# LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.**
For output encoding see Anti-XSS.
For LDAP encoding see Anti-XSS.

**DISCLAIMER:** This library is opinionated in favor of en-US culture and ASCII-compatible characters. Support for international unicode character cleansing is out-of-scope for me at the moment. This is built with .NET 4.6.1 so as to be compatible with legacy .NET applications. (A newer version targeting C# 7 and .Netcore could be beneficial, leveraging Span T for better performance and Memory T for async support.)

**Use this to:** sanitize the arguments passed in to a Console application or sanitize the values read out of a configuration file, such as application settings or a connection string.

**Caveat:** This should likely be combined with digitally signing any .exe or .dll files (so that a hacker couldn't just call into any .dll that hasn't been signed at will.)

**Threat vector:** a hacker who first succeeds in penetrating a network may seek to pivot to other valuable resources or to steal (and exfiltrate) database data. To do so, they may try to run a console app on a given server with random, malicious parameters to see what it may do. Or, they may try to tamper with a web server's configuration file to bypass a web application's authentication or role authorization restrictions. They may also seek to point any configurable email addresses to their own email address with a different domain.

**ADVICE:** Validate all input

**RE-STATED:** Developers often don't validate all input. 
They take the shotgun parser approach where they assume input is well-formed, whereas a recognizer would verify input as well-formed.
LANGSEC-Language-theoretic Security: treat all valid or expected inputs as a formal language and the input-handling routines as a recognizer for that language.
A recognizer could be built using a lexer to break an input string up into contextual tokens (e.g. string literal, number), followed by a parser to analyze the sequence of tokens to determine whether or not the sequence conforms to a given grammar.

However, in the context of ModestSanitizer, I am not parsing anything greater than parameter strings. The sweet spot for this C# code library is maybe parsing string arguments from a legacy console app in order to compare either against (1) an expected format, simple enough to be matched by a Regex expression or against (2) an expected string or list of strings.

So, I haven't built a full-blown lexer or parser, but have merely leveraged the String Equals, or the String IndexOf with StringComparison of OrdinalIgnoreCase (for case insensitive equals), to tokenize and parse in simplest fashion after first either (1) normalizing the unicode or preferably (2) limiting the unicode to ASCII-like (letterlike) characters for security reasons. Unicode has a much greater array of potentially malicious and/or misleading characters.

Overall, I see the process of validating input securely as having two steps: **1. Sanitization and 2. Input Validation**.

**EXAMPLE:** 
1. If converting a string to an Integer, I want to sanitize it to only accept a valid minimum of -2147483648 with a valid maximum of 2147483647.
2. Then I may want to perform input validation because let's say in my application the valid values happen to be only from 0 to 1000.

It may be worth separating these out because we may want to monitor anomalous (potentially malicious) activity vs. expected common validation errors.
With expected validation errors we also typically want to report back to a user. Whereas with anomalous data we may just wish to log and alert security.

**CODE:**
```
Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);

String potentiallyMaliciousString = "äiti®";
String stringLimitedToLetterlikeChars = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString);

//Removes the accent from the 'a', but removes the copyright symbol altogether
Assert.AreEqual("aiti", stringLimitedToLetterlikeChars); 

//ready for comparison against a whitelist!
```

Always try to look for loopholes in your whitelisting efforts.

# ModestSanitizer Usage

The ModestSanitizer is defined to sanitize input parameters in multiple steps.

* The first step is to truncate to a predefined character limit. The developer should also check for NULL values or empty strings at this point since Modest Sanitizer will typically return null if a null is passed in.

* The second step is to review (and log/alert on) the input strings against any appropriate blacklists. This step should likely be set to TrackExceptionsInList only so as not to automatically (but only optionally based on developer discretion) stop the program if a malicious string is found. This is primarily a monitoring and cleansing step. The following steps would maybe be a more appropriate place to perform a full stop if an exception is found. The returned string will be cleansed of blacklist tokens.

* The third step (MinMax) is to convert from strings to other data types, as needed, doing so with pre-defined minimum and maximum values.

* The fourth step for the remaining strings is to normalize them to FormKC. Unicode can represent certain characters as either two characters (e.g. an accent and a letterlike character) or one (e.g. a single character representing the combined accent and letterlike character) depending on the form used. By normalizing to a single form, it is then easier to reliably compare against a whitelist. 

Alternatively, the strings may instead be limited to just a subset of ASCII characters 32-126, the letterlike or numberlike characters, mathematical operators, and punctuation marks. This again provides even greater reliability when comparing against a whitelist at the expense of being less viable in international scenarios where Unicode may be required.

* The fifth and most important step (when possible) is to define a set of whitelist values and compare these against the now normalized/limited strings of input. This step should likely be set to ThrowExceptions and stop the program or escalate to support/security any true mismatches. FileNameCleanse may also be performed at this step. If whitelist values are NOT possible then at a minimum, at least the format of the input strings should be validated using Regex expressions. 


