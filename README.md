
# ModestSanitizer
**REASONABLY SECURE GENERAL PURPOSE C# LIBRARY TO SANITIZE INPUT THAT DOES NOT REQUIRE OUTPUT ENCODING.**
- For output encoding see Anti-XSS.
- For LDAP encoding see Anti-XSS.

**DISCLAIMER:** This library is opinionated in favor of en-US culture and ASCII-compatible characters. Support for international unicode character cleansing is limited. This is built with .NET 4.6.1 so as to be compatible with legacy .NET applications. (A newer version targeting C# 7 and .Netcore could be beneficial, leveraging Span T for better performance and Memory T for async support.)

**USE THIS TO:** sanitize the arguments passed in to a Console application, or string parameters in general, or sanitize the values read out of a configuration file, such as application settings or a connection string.

**CAVEAT:** This should likely be combined with digitally signing any .exe or .dll files (so that a hacker can't tamper with them.) Also, I ship this Nuget package with the .pdb file included for convenience, but you may wish to remove this file prior to deploying to Production!

## **Why sanitize?**
**THREAT VECTOR:** a hacker :smiling_imp: who first succeeds in penetrating a network may seek to pivot to other valuable resources or to steal (and exfiltrate) database data. To do so, they may try to run a console app on a given server with random, malicious parameters to see what it may do. Or, they may try to tamper with a web server's configuration file to bypass a web application's authentication or role authorization restrictions. They may also seek to point any configurable email addresses to their own email address with a different domain. This library is a small step to try to prevent that.

**THE ADVICE:**   :small_blue_diamond: Sanitize and then validate all input

**RE-STATED:**   :small_red_triangle_down: Developers often don't validate all input. 

They take the shotgun parser approach where they assume input is well-formed, whereas a recognizer would verify input as well-formed. _LANGSEC-Language-theoretic Security_ advises that we should treat all valid or expected inputs as a formal language and the input-handling routines as a recognizer for that language. A recognizer could be built using a lexer to break an input string up into contextual tokens (e.g. string literal, or number, or . . . ), followed by a parser to analyze the sequence of tokens to determine whether or not the sequence conforms to a given grammar.

However, in the context of ModestSanitizer, I am typically not parsing anything greater than console app arguments, or string parameters, or app settings to compare against either:
1. An expected format, simple enough to be matched by a Regex expression. 
2. An expected valid string or list of strings.

I haven't built a full-blown lexer or parser, but have merely leveraged the **String Equals**, or the **String IndexOf** with StringComparison of OrdinalIgnoreCase (for case insensitive equals), to parse and compare in simplest fashion. This is completed after first either:
1. Normalizing the Unicode.
2. Limiting the Unicode to ASCII-like (letterlike) characters.  
_NOTE: Unicode has a much greater array of potentially malicious and/or misleading characters._

## **Example Scenario** 
Overall, I see the process of validating input securely as having two steps: 
* :star: **Sanitization**
* :star: **Input Validation**

For instance:
1. If converting a string to an Integer, sanitize it to only accept a valid minimum of -2147483648 with a valid maximum of 2147483647.
2. Then perform input validation because in my application the valid values happen to be only from 0 to 1000.

Separate these out to address separate concerns. Monitor anomalous (potentially malicious) activity during the sanitize step. Check for appropriate values based on app or business rules during the validation step. With anomalous data we may wish cleanse it, log it (the cleansed version), and alert security. With validation errors we may want to report back to the user thru a user interface (UI) for them to perform corrections. 

## **Example Code**
```
using System;
using System.Collections.Generic;
using ModestSanitizer;
using static ModestSanitizer.Sanitizer;

namespace ConsoleApp1
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                Sanitizer sanitizerReviewOnly = new Sanitizer(SaniCore.Approach.TrackExceptionsInList, false);

                String result1 = null;
                String cleanResult1 = null;
                String dateResult = null;
                String decimalResult = null;
                DateTime ? cleanDateResult = null;
                Decimal? cleanDecimalResult = 0;

                try
                {
                    if ( args[0] == null || args[1] == null || args[2] == null)
                    {
                        throw new ArgumentNullException("Args cannot be null!");
                    }

                    //Step one: TRUNCATE
                    result1 = sanitizerReviewOnly.Truncate.ToValidLength(args[0], 9);
                    dateResult = sanitizerReviewOnly.Truncate.ToValidLength(args[1], 10);
                    decimalResult = sanitizerReviewOnly.Truncate.ToValidLength(args[2], 7);

                    //Step Two: RESTRICTEDLIST.
                    bool checkForHexChars = true;
                    bool checkForCommonMaliciousChars = true;

                    //ModestSanitizer doesn't automatically disallow Forward Slash and Tilde since valid FilePaths may contain these.
                    //However, if you aren't passing a FilePath then it may make sense to add these to your own RestrictedList as shown here.
                    List<string> RestrictedListForwardSlashAndTilde = new List<string>() { "\\", "~" };

                    if ((bool)sanitizerReviewOnly.RestrictedList.ReviewIgnoreCaseUsingASCII(ref result1, RestrictedListForwardSlashAndTilde, 10, 
                        checkForHexChars, checkForCommonMaliciousChars))
                    {
                        //Log the reviewed value (cleansed) that had RestrictedList substrings found (and removed) and notify IT security.
                        Console.WriteLine("RestrictedList matched! Notify IT security. Value: " + result1);
                    }
                    else
                    {
                        Console.WriteLine("RestrictedList values not found. Proceed. Value: " + result1);
                    }
                    sanitizerReviewOnly.ClearSaniExceptions(); //Since some values are stored in the exception list, it is a good idea to clear it.

                    //Now let's switch to throwing exceptions instead of merely logging them . . .
                    Sanitizer sanitizer = new Sanitizer(SaniCore.Approach.ThrowExceptions, false);
           
                    //Step Three: CONVERT.
                    cleanDateResult = sanitizer.MinMax.DateTimeType.ToValidValueUSDefault(dateResult, DateUtil.DataType.Date);
                    Console.WriteLine("Date is valid and matches expected format! Value: " + cleanDateResult);

                    cleanDecimalResult = sanitizer.MinMax.DecimalType.ToValidValue(decimalResult, 99999999M, 0M, false);
                    Console.WriteLine("Decimal is valid! Value: " + decimalResult);

                    //Step Four: NORMALIZE OR LIMIT.
                    cleanResult1 = sanitizer.NormalizeOrLimit.ToASCIIOnly(result1);

                    //Step Five: ALLOWED LIST.
                    //AllowedList performs the NormalizeOrLimit.ToASCIIOnly too. Explicitly call this above just for clarity.
                    if ((bool)sanitizer.AllowedList.ASCII.Matches(ref cleanResult1, "myReport", 10)) //truncates again too.
                    {
                        Console.WriteLine("AllowedList matched! Value: " + cleanResult1);
                    }
                    else
                    {
                        Console.WriteLine("Notify security allowedList violation occurred! Value: " + cleanResult1);
                    }
                }
                catch (SanitizerException ex)
                {
                    Console.WriteLine("SanitizerException: " + ex.Message);
                }

                //Proceed with cleansed data . . .
                Console.WriteLine(cleanResult1 + " is the report identified to run.");
                Console.WriteLine(cleanDateResult.ToString() + " is the date to run the report for.");
                System.Globalization.CultureInfo enUS = System.Globalization.CultureInfo.GetCultureInfo("en-US");
                Console.WriteLine(((decimal)cleanDecimalResult).ToString("C2", enUS) + " is the preferred dollar amount.");

                //if (System.Diagnostics.Debugger.IsAttached) 
                Console.ReadLine();
            }
        }
    }
}
```

Always try to look for loopholes in terms of your Allowed List or Regex. 

Also, try to look for overlaps in your Restricted List. The order in which the string is cleansed may impact your Restricted List review. If your Restricted List contains common malicious characters (such as a null byte) that ModestSanitizer removes prior to comparing values, a loophole could be introduced. Test for this!

## Usage Guidelines

The ModestSanitizer is designed to sanitize input strings in multiple steps.

- :star: **Step One:  TRUNCATE.** The first step is to truncate to a predefined character limit. The developer should also check for NULL values or empty strings at this point since Modest Sanitizer will typically just return null if a null or whitespace is passed in.

* :star: **Step Two: RESTRICTED LIST.** The second step is to review (and log/alert on) the input strings against any appropriate Restricted Lists. This step should likely be set to TrackExceptionsInList only so as not to automatically stop the program if a malicious string is found (but only optionally based on developer discretion.) This is primarily a monitoring and cleansing step. The following steps would likely be a more appropriate place to perform a full stop if an exception is found. The returned string will be cleansed of RestrictedList tokens and available by ref.

* :star: **Step Three: CONVERT.** The third step (MinMax) is to convert from strings to other data types, as needed, doing so with pre-defined minimum and maximum values.

* :star: **Step Four: NORMALIZE OR LIMIT.** The fourth step for the remaining strings is to normalize them to FormKC. Unicode can represent certain characters as either two characters (e.g., an accent and a letterlike character) or one (e.g., a single character representing the combined accent and letterlike character) depending on the form used. By normalizing to a single form, it is then easier to reliably compare against an Allowed List. 

Alternatively, the strings may instead be limited to just a subset of ASCII characters 32-126, the letterlike or numberlike characters, mathematical operators, and punctuation marks. This again provides even greater reliability when comparing against an Allowed List at the expense of being less viable in international scenarios where Unicode may be required.

* :star: **Step Five: ALLOWED LIST.** The fifth and most important step (when possible) is to define a set of Allowed List values and to compare these against the now normalized/limited strings of input. (It also may be potentially worthwhile to review a Restricted List again prior to matching against the Allowed List, now that you've normalized/limited.) This Allowed List step should likely be set to ThrowExceptions and stop the program or escalate to support/security any true mismatches. FileNameCleanse may also be performed at this step. If Allowed List values are NOT possible then at a minimum, at least the format of the input strings should be validated using a Regex expression. 
## What Modest Sanitizer is Meant to Address
1. Check inputs against Allowed List of valid values using ASCII or Unicode.
**Why?** To safely compare input string(s) to expected, valid values to prevent invalid or malicious values. 

NOTE: This is NOT meant to replace (but merely to supplement) formal input validation such as by adding annotations to your Model in C#, see here:  [https://docs.microsoft.com/en-us/aspnet/mvc/overview/older-versions/getting-started-with-aspnet-mvc3/cs/adding-validation-to-the-model](https://docs.microsoft.com/en-us/aspnet/mvc/overview/older-versions/getting-started-with-aspnet-mvc3/cs/adding-validation-to-the-model)

2. Check input File Names via Regex using ASCII (letterlike) characters.
**Why?** To assist with cleansing filenames of invalid or malicious characters such as null bytes or characters that reverse order to Right-To-Left.
3. Check input numbers (and dates) against a valid minimum and maximum value (and check date formats.)
**Why?** To protect against buffer overflow attacks if using the unsafe keyword (e.g., if marshaling data to unmanaged memory): https://stackoverflow.com/questions/9343665/are-buffer-overflow-exploits-possible-in-c. (Also, to assure that strings converted to dates follow a valid format.)
4. Assure that Unicode is normalized to FormKC or limited to a subset of ASCII (letterlike) characters.
**Why?** To assist with safe, reliable comparing of inputs against Allowed List of valid values.
5. Throw exception if Restricted List value found in inputs or merely track/monitor/cleanse inputs of potentially malicious characters and log the cleansed values.
**Why?** To assist with monitoring, tracking, and cleansing of potentially malicious input
6. Truncate input strings to a valid max length.
**Why?** To protect against malicious hackers passing-in gigabyte-length strings which could potentially slow down the sanitizing process or the application itself.

ModestSanitizer is NOT meant to replace or compete with a full-blown, mature, robust **runtime application self-protection (RASP)** library or tool, see here:
[https://en.wikipedia.org/wiki/Application_security](https://en.wikipedia.org/wiki/Application_security)

