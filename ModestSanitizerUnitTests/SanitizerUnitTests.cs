using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ModestSanitizer;
using static ModestSanitizer.SaniCore;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizerUnitTests
{
    [TestClass]
    public class SanitizerUnitTests
    {
        [TestMethod]
        public void Test_ReduceToValidMaxMinValue()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);

            string utcStringWithTimeZone = DateUtil.GetNowFormattedAsUTCStringWithTimeZone();
           
            DateTime? resultUTCWithTimeZone = sanitizer.MinMax.DateTimeType.ToValidValue(utcStringWithTimeZone, new DateTime(2050, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithSeconds, DateUtil.Delim.UTCWithDelimitersAndZone, MinMax.DateFormat.None, false);

            Assert.AreEqual(utcStringWithTimeZone, resultUTCWithTimeZone.Value.ToString("yyyy-MM-dd'T'HH:mm:ssK"));

            DateTime? resultSQLServerDateTime = sanitizer.MinMax.DateTimeType.ToValidValueUSDefault("1700-01-25 16:01:36.000", DateUtil.DataType.SQLServerDateTime, DateUtil.Delim.Dash, MinMax.DateFormat.SQLServer);

            Assert.AreEqual(new DateTime(1753, 1, 1, 0, 0, 0), resultSQLServerDateTime);

            DateTime? resultDateInUSFormat = sanitizer.MinMax.DateTimeType.ToValidValueUSDefault("1/25/1970", DateUtil.DataType.Date);

            Assert.AreEqual(new DateTime(1970, 1, 25, 0, 0, 0), resultDateInUSFormat);

            DateTime? resultDateInEuroFormat = sanitizer.MinMax.DateTimeType.ToValidValue("26-01-1970", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.Date, DateUtil.Delim.Dash, MinMax.DateFormat.Euro, false);

            Assert.AreEqual(new DateTime(1970, 1, 26, 0, 0, 0), resultDateInEuroFormat);

            DateTime? resultDateInChineseFormat = sanitizer.MinMax.DateTimeType.ToValidValue("2009.06.15", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.Date, DateUtil.Delim.Dot, MinMax.DateFormat.China, false);

            Assert.AreEqual(new DateTime(2009, 6, 15, 0, 0, 0), resultDateInChineseFormat);
            
            DateTime? resultDateInUSFormatWithTime = sanitizer.MinMax.DateTimeType.ToValidValue("02/18/1953 15:15", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTime, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, false);

            Assert.AreEqual(new DateTime(1953, 2, 18, 15, 15, 0), resultDateInUSFormatWithTime);

            DateTime? resultDateInUSFormatWithTimeSeconds = sanitizer.MinMax.DateTimeType.ToValidValue("06/08/1953 15:15:33", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithSeconds, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, false);

            Assert.AreEqual(new DateTime(1953, 6, 8, 15, 15, 33), resultDateInUSFormatWithTimeSeconds);

            DateTime? resultDateInUSFormatWithTimeSecondsAMPM = sanitizer.MinMax.DateTimeType.ToValidValue("06/15/2009 03:05:03 PM", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithSeconds, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, true);

            Assert.AreEqual(new DateTime(2009, 6, 15, 15, 5, 3, 0), resultDateInUSFormatWithTimeSecondsAMPM);

            DateTime? resultDateInUSFormatWithTimeMilliseconds = sanitizer.MinMax.DateTimeType.ToValidValue("06/05/2009 03:05:03.003", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithMilliseconds, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, false);

            Assert.AreEqual(new DateTime(2009, 6, 5, 3, 5, 3, 3), resultDateInUSFormatWithTimeMilliseconds); //since no AM or PM specified, the above is 3:05 AM.

            DateTime? resultDateInUSFormatWithTimeMillisecondsAMPM = sanitizer.MinMax.DateTimeType.ToValidValue("06/05/2009 03:05:03.003 PM", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithMilliseconds, DateUtil.Delim.ForwardSlash, MinMax.DateFormat.US, true);

            Assert.AreEqual(new DateTime(2009, 6, 5, 15, 5, 3, 3), resultDateInUSFormatWithTimeMillisecondsAMPM); //this is 3:05 PM or 15:05 in 24-hr time

            DateTime? resultDateTimeWithUTCWithDelimiters = sanitizer.MinMax.DateTimeType.ToValidValue("2015-12-08T15:15:19", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithSeconds, DateUtil.Delim.UTCWithDelimiters, MinMax.DateFormat.US, false);

            Assert.AreEqual(new DateTime(2015, 12, 8, 15, 15, 19), resultDateTimeWithUTCWithDelimiters);

            DateTime? resultDateTimeWithUTCWithoutDelimiters = sanitizer.MinMax.DateTimeType.ToValidValue("20151208T151519", new DateTime(2999, 1, 1), new DateTime(1753, 1, 1), DateUtil.DataType.DateTimeWithSeconds, DateUtil.Delim.UTCWithoutDelimiters, MinMax.DateFormat.US, false);
           
            Assert.AreEqual(new DateTime(2015, 12, 8, 15, 15, 19), resultDateTimeWithUTCWithoutDelimiters);

            decimal? resultDollarSign = sanitizer.MinMax.DecimalType.ToValidValue("-$100,000.00", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xCommaxDotx);

            Assert.AreEqual(-100000.00M, resultDollarSign);

            decimal? resultNegativeSign = sanitizer.MinMax.DecimalType.ToValidValue("-1 220.5365$", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xSpacexDotx);

            Assert.AreEqual(-1220.5365M, resultNegativeSign);

            decimal? resultDotComma = sanitizer.MinMax.DecimalType.ToValidValue("€120.000,99", 999999999999.99M, 0.00M, false, MinMax.CurrencySeparators.xDotxCommax);

            Assert.AreEqual(120000.99M, resultDotComma);

            decimal? resultSpaceComma = sanitizer.MinMax.DecimalType.ToValidValue("€120 000,995", 999999999999.99M, 0.00M, false, MinMax.CurrencySeparators.xSpacexCommax);

            Assert.AreEqual(120000.995M, resultSpaceComma);

            decimal? resultSpace = sanitizer.MinMax.DecimalType.ToValidValue("-20 000 $", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xSpacexDotx);

            Assert.AreEqual(-20000M, resultSpace);

            decimal? resultSpace2 = sanitizer.MinMax.DecimalType.ToValidValue("($20,000)", 999999999999.99M, -19000.00M, true);

            Assert.AreEqual(-19000M, resultSpace2);

            decimal? resultInvalidLeadZeroes = sanitizer.MinMax.DecimalType.ToValidValue("$00,012.7", 999999999999.99M, 0.00M, true);

            Assert.AreEqual(12.7M, resultInvalidLeadZeroes);
  
            int ? result = sanitizer.MinMax.IntegerType.ToValidValue("5", 4, 0);

            Assert.AreEqual(4, result);

            int? result2 = sanitizer.MinMax.IntegerType.ToValidValue("4", 4, 0);

            Assert.AreEqual(4, result2);

            int? result3 = sanitizer.MinMax.IntegerType.ToValidValue("3", 4, 0);

            Assert.AreEqual(3, result3);

            int? resultNull = sanitizer.MinMax.IntegerType.ToValidValue(null, 50, 0);

            Assert.AreEqual(null, resultNull);

            int? result4 = sanitizer.MinMax.IntegerType.ToValidValue("-51", 50, -50);

            Assert.AreEqual(-50, result4);

            int? result5 = sanitizer.MinMax.IntegerType.ToValidValue("-49", 50, -50);

            Assert.AreEqual(-49, result5);

            bool wasExceptionThrown = false;
            try
            {
                sanitizer.MinMax.IntegerType.ToValidValue("999999999999999999999999999999999", 50, -50);
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            sanitizer.ClearSaniExceptions();

            Sanitizer sanitizer2 = new Sanitizer(Approach.TrackExceptionsInList, true);

            try
            {
                sanitizer2.MinMax.IntegerType.ToValidValue("999999999999999999999999999999999", 50, -50);
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            KeyValuePair<SaniTypes, string> kvp =  sanitizer2.SaniExceptions.Values.FirstOrDefault<KeyValuePair<SaniTypes, string>>();
            Assert.AreEqual(SaniTypes.MinMax, kvp.Key);
            Assert.AreEqual("MinMax: 9999999999 Exception: Parse Failure.", kvp.Value);

            bool? result6 = sanitizer.MinMax.BooleanType.ToValidValue("false");

            Assert.AreEqual(false, result6);

            bool? result7 = sanitizer.MinMax.BooleanType.ToValidValue(" ");

            Assert.AreEqual(null, result7);

            bool? result8 = sanitizer.MinMax.BooleanType.ToValidValue("True");

            Assert.AreEqual(true, result8);

            wasExceptionThrown = false; //re-set flag

            try
            {
                bool? result9 = sanitizer.MinMax.BooleanType.ToValidValue("1");
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            try
            {
                bool? result10 = sanitizer.MinMax.BooleanType.ToValidValue("a bad value");
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag   

            sanitizer2.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_AllowedListEquals()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);
            bool wasExceptionThrown = false;
            string innerExceptionMsg = String.Empty;

            string stringToCheck = "farside";
            bool? result = sanitizer.AllowedList.ASCII.EqualsValue(ref stringToCheck, "farside", 7);

            Assert.AreEqual(true, result);
            Assert.AreEqual("farside", stringToCheck);

            bool? result2 = sanitizer.AllowedList.ASCII.EqualsValueIgnoreCase(ref stringToCheck, "farSiDe", 7);

            Assert.AreEqual(true, result2);

            stringToCheck = "farside";
            try 
            { 
                bool? result3 = sanitizer.AllowedList.ASCII.EqualsValue(ref stringToCheck, "farSiDe", 7);

                Assert.AreEqual(false, result3);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck does NOT equal allowedList value.", innerExceptionMsg);

            stringToCheck = "farside";
            bool? result4 = sanitizer.AllowedList.ASCII.EqualsValue(ref stringToCheck, "far", 3);

            Assert.AreEqual(true, result4);
            Assert.AreEqual("far", stringToCheck);

            stringToCheck = "faRside";
            bool? result5 = sanitizer.AllowedList.ASCII.EqualsValueIgnoreCase(ref stringToCheck, "far", 3);

            Assert.AreEqual(true, result5);
            Assert.AreEqual("far", stringToCheck);

            stringToCheck = @"\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a\x61\x6c\x65\x72\x74\x281337\x29";
            bool? result6 = sanitizer.AllowedList.Unicode.EqualsValue(ref stringToCheck, @"\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a\x61\x6c\x65\x72\x74\x281337\x29", 250);

            Assert.AreEqual(true, result6);

            //NOTE: This Unicode string is NOT equal since it was NOT prepended with an @ verbatim symbol. This causes a variance of \ versus \\
            //Be careful of this in your allowlist comparisons.
            Assert.AreNotEqual("\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a\x61\x6c\x65\x72\x74\x281337\x29", stringToCheck);

            stringToCheck = "Delta Δ and Pi(\u03a0) and Sigma(\u03a3)"; //Δ  is Delta capital letter. δ is Delta lower case letter. Equal when ignore case.
            bool? result7 = sanitizer.AllowedList.Unicode.EqualsValueIgnoreCase(ref stringToCheck, "Delta δ and Pi(\u03a0) and Sigma(\u03a3)", 250);

            Assert.AreEqual(true, result7);
            //NOTE: stringToCheck reverts to the AllowList version in terms of case. This is to favor the expected case.            
            Assert.AreEqual("Delta δ and Pi(\u03a0) and Sigma(\u03a3)", stringToCheck);

            //.NET recognizes the C - \u0063 and the exclamation point \x0021 as Unicode characters here. Successfuly converts to ASCII.
            string stringToCheckSuffix = "He said, \"This is the last \u0063hance\x0021\"";
            bool? resultSuffix = sanitizer.AllowedList.ASCII.EndsWithSuffix(ref stringToCheckSuffix, "\u0063hance\x0021\"", 46);

            Assert.AreEqual(true, resultSuffix);
            Assert.AreEqual("He said, \"This is the last \u0063hance\x0021\"", stringToCheckSuffix);

            //Due to the verbatim @ symbol, .NET fails to recognize the C - \u0063 and the exclamation point \x0021 as Unicode characters here.
            //However, since we use the Unicode version of the method and there is no attempt to convert to ASCII, this works fine.
            string stringToCheckSuffix2 = @"He said, ""This is the last \u0063haNce\x0021""";
            bool? resultSuffix2 = sanitizer.AllowedList.Unicode.EndsWithSuffixIgnoreCase(ref stringToCheckSuffix2, @"\u0063hAnCe\x0021""", 50);

            Assert.AreEqual(true, resultSuffix2);
            Assert.AreEqual(@"He said, ""This is the last \u0063haNce\x0021""", stringToCheckSuffix2);

            string stringToCheckPrefix = "HelloWorld";
            bool? resultPrefix = sanitizer.AllowedList.ASCII.StartsWithPrefix(ref stringToCheckPrefix, "Hello", 7);

            Assert.AreEqual(true, resultPrefix);
            Assert.AreEqual("HelloWo", stringToCheckPrefix); //truncated to 7 characters. Prefix was met even after truncating.

            string stringToCheckPrefix2 = @"hEllo WORld";
            bool? resultPrefix2 = sanitizer.AllowedList.Unicode.StartsWithPrefixIgnoreCase(ref stringToCheckPrefix2, @"Hello World", 50);

            Assert.AreEqual(true, resultPrefix2);
            Assert.AreEqual(@"hEllo WORld", stringToCheckPrefix2);

            sanitizer.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_RestrictedListReview()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);
            bool wasExceptionThrown = false;
            string innerExceptionMsg = String.Empty;

            //Hex value for 'javascript:alert(1337)'
            string hexValue = (@"\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a\x61\x6c\x65\x72\x74\x281337\x29");

            try
            {
                List<string> plainTextRestrictedList = new List<string>
                {
                    @"javascript: alert(1337)",
                    @"javascript",
                    @"alert"
                };

                bool checkForStandardHexRestrictedListChars = false;

                bool? result1 = sanitizer.RestrictedList.ReviewIgnoreCaseUsingASCII(ref hexValue, plainTextRestrictedList, 225, checkForStandardHexRestrictedListChars, false);

                Assert.AreEqual(false, result1); //no match since NOT checking for standard hex characters in the restrictedList

                checkForStandardHexRestrictedListChars = true;

                bool? result2 = sanitizer.RestrictedList.ReviewIgnoreCaseUsingASCII(ref hexValue, plainTextRestrictedList, 225, checkForStandardHexRestrictedListChars, true);

                Assert.AreEqual(true, result2); //match true on hex char \x since bool to check for standard hex restrictedList chars was set to true.
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck contains a restrictedList value.", innerExceptionMsg);
            Assert.AreEqual(hexValue, @"6a6176617363726970743a616c65727428133729");

            wasExceptionThrown = false; //re-set flag
            innerExceptionMsg = String.Empty; //re-set msg

            string stringWithNullByte = @"\\cmy%pURL%00.biz";

            try
            {
                List<string> plainTextRestrictedList = new List<string>
                {
                    @"\\c" //NOTE: this resolves to this \\\\c due to the @. Without the asterisk verbatim string it will resolve to \\c
                };

                bool checkForCommonMaliciousChars = false;

                bool? result3 = sanitizer.RestrictedList.ReviewIgnoreCaseUsingASCII(ref stringWithNullByte, plainTextRestrictedList, 225, false, checkForCommonMaliciousChars);

                Assert.AreEqual(false, result3); //this line will never be reached since SanitizerException thrown since restrictedList matched.
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck contains a restrictedList value.", innerExceptionMsg);

            //since we didn't check for common malicious chars it only removed the restrictedList value \\c
            Assert.AreEqual(@"my%pURL%00.biz", stringWithNullByte); 

            string stringWithNullByteAgain = @"\\cmy%pURL%00.biz";

            try
            {
                List<string> plainTextRestrictedList2 = new List<string>
                {
                    @"\c" //NOTE: this resolves to this \\\\c due to the @. Without the asterisk verbatim string it will resolve to \\c
                };

                bool checkForCommonMaliciousCharsTrue = true; //let's check for common malicious characters this time

                bool? result4 = sanitizer.RestrictedList.ReviewIgnoreCaseUsingASCII(ref stringWithNullByteAgain, plainTextRestrictedList2, 225, true, checkForCommonMaliciousCharsTrue);

                Assert.AreEqual(true, result4); //match true on null byte %00 since bool to check for common malicious characters restrictedList was set to true.

            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck contains a common malicious character and a restrictedList value.", innerExceptionMsg);

            Assert.AreEqual(@"myURL.biz", stringWithNullByteAgain);//clears common malicious characters %p and %00 plus restrictedList value \\c this time

            sanitizer.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_TruncateToValidLength()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);
            String result = sanitizer.Truncate.ToValidLength("testBigger", 4);

            Assert.AreEqual("test", result);

            String result2 = sanitizer.Truncate.ToValidLength("test", 4);

            Assert.AreEqual("test", result2);

            String result3 = sanitizer.Truncate.ToValidLength("testSmaller", 50);

            Assert.AreEqual("testSmaller", result3);

            String resultNull = sanitizer.Truncate.ToValidLength(null, 50);

            Assert.AreEqual(null, resultNull);

            String resultStrEmpty = sanitizer.Truncate.ToValidLength(String.Empty, 50);

            Assert.AreEqual(null, resultStrEmpty);

            sanitizer.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_NormalizeUnicode()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);
            String result = sanitizer.NormalizeOrLimit.NormalizeUnicode("äiti");

            //Normalize to the nfkc format of Unicode
            Assert.AreEqual("\u00e4\u0069\u0074\u0069", result); //'äiti' in unicode characters of nfkc normalization form.

            //FYI, other types of Unicode formats: nfkd, nfc, and nfd
            //Assert.AreEqual("\u0061\u0308\u0069\u0074\u0069", result); //nfkd
            //Assert.AreEqual("\u00e4\u0069\u0074\u0069", unorm.nfc(str));
            //Assert.AreEqual("\u0061\u0308\u0069\u0074\u0069", unorm.nfd(str));

            //The idea here is to have a reliable allowedList (for comparison purposes)
            String potentiallyMaliciousString = "script";
            String normalizedString = sanitizer.NormalizeOrLimit.NormalizeUnicode(potentiallyMaliciousString); //normalize to nfkc format

            String allowedList = "\u0073\u0063\u0072\u0069\u0070\u0074"; //'script' in unicode characters of nfkc normalization form.

            Assert.AreEqual(allowedList, normalizedString); //compare

            sanitizer.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_ToASCIIOnly()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);

            //Another approach to have a reliable allowedList (for comparison purposes)
            String potentiallyMaliciousString = "äiti®";

            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars = sanitizer.NormalizeOrLimit.ToASCIIOnly(potentiallyMaliciousString);

            //Removes the accent from the 'a', but removes the copyright symbol altogether
            Assert.AreEqual("aiti", stringLimitedToLetterlikeChars); //compare

            String potentiallyMaliciousString2 = @"&euml;,ä,&ccedil;,!@#$%^%&*(*)__+~!`';,./<>\|}{-=/*-+.,./?";

            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars2 = sanitizer.NormalizeOrLimit.ToASCIIOnly(potentiallyMaliciousString2);

            //Removes the accent from the 'a'
            Assert.AreEqual(@"&euml;,a,&ccedil;,!@#$%^%&*(*)__+~!`';,./<>\|}{-=/*-+.,./?", stringLimitedToLetterlikeChars2); //compare
             
            String potentiallyMaliciousString3 = "U, Ù, Ú, Û, ñ, Ü, Ů, ç, Ő";
                                                     
            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars3 = sanitizer.NormalizeOrLimit.ToASCIIOnly(potentiallyMaliciousString3);

            //Removes the accent marks from the unicode characters U, n, c O
            Assert.AreEqual("U, U, U, U, n, U, U, c, O", stringLimitedToLetterlikeChars3); //compare

            String potentiallyMaliciousString4 = "È,É,Ê,Ë,Û,Ù,Ï,Î,À,Â,Ô,è,é,ê,ë,û,ù,ï,î,à,â,ô";

            String stringLimitedToLetterlikeChars4 = sanitizer.NormalizeOrLimit.ToASCIIOnly(potentiallyMaliciousString4);

            //Removes the accent marks from the unicode characters E, U, I, A, O including lower case versions
            Assert.AreEqual("E,E,E,E,U,U,I,I,A,A,O,e,e,e,e,u,u,i,i,a,a,o", stringLimitedToLetterlikeChars4); //compare
            
            //Malicious leading Unicode characters prepended to 'script' in unicode characters of nfkc normalization form.
            String potentiallyMaliciousString5 = "踰\u000D\u0000\u202E\u0073\u0063\u0072\u0069\u0070\u0074"; 
            String stringLimitedToLetterlikeChars5 = sanitizer.NormalizeOrLimit.ToASCIIOnly(potentiallyMaliciousString5);

            Assert.AreEqual("\u0073\u0063\u0072\u0069\u0070\u0074", stringLimitedToLetterlikeChars5); //retains only chars C# matches to ASCII subset   

            sanitizer.ClearSaniExceptions();
        }

        [TestMethod]
        public void Test_SanitizeViaRegexUsingASCII()
        {
            Sanitizer sanitizer = new Sanitizer(Approach.ThrowExceptions, true);
            bool wasExceptionThrown = false;
            string innerExceptionMsg = String.Empty;

            try
            {
                //Test #1 - test potentially malicious non-breaking space \u00A0 character
                string result = sanitizer.FileNameCleanse.SanitizeViaRegexUsingASCII("secretdoc \u00A0.pdf", 20, true, ".pdf",false,false,false,false,false);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("Filename contains potentially malicious characters.", innerExceptionMsg);

            wasExceptionThrown = false; //re-set flag

            try
            {
                //Test #2 - throw exception due to trailing dot
                string result = sanitizer.FileNameCleanse.SanitizeViaRegexUsingASCII("my presentationpptx.", 21, false, null, true, false, false, false, false);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("Filename is NOT a valid Windows filename.", innerExceptionMsg);

            wasExceptionThrown = false; //re-set flag

            try
            {
                //Test #3 - throw exception for more than one dot
                sanitizer.FileNameCleanse.SanitizeViaRegexUsingASCII("secret.doc .pdf", 20, true, ".pdf", false, false, false, false, false);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("Filename contains more than one dot character.", innerExceptionMsg);

            wasExceptionThrown = false; //re-set flag

            //Test #4 - green case - valid filename
            string result4 = sanitizer.FileNameCleanse.SanitizeViaRegexUsingASCII("my.report.05-29-2020.pdf", 25, false, ".pdf", false, false, false, false, false);
            Assert.AreEqual("my.report.05-29-2020.pdf", result4);

            //Test #5 - green case - valid filename - chopping off date
            string result5 = sanitizer.FileNameCleanse.SanitizeViaRegexUsingASCII("  myfile.txt05-29-2020", 12, false, ".txt", false, false, false, false, false);
            Assert.AreEqual("  myfile.txt", result5);

            sanitizer.ClearSaniExceptions();

            Sanitizer sanitizer2 = new Sanitizer(Approach.TrackExceptionsInList, true);

            try
            {
                //Test #6 - should track exception for no file extension
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII(null, 50, false, null, true, true, true, true, true);
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            KeyValuePair<SaniTypes, string> kvp = sanitizer2.SaniExceptions.Values.FirstOrDefault<KeyValuePair<SaniTypes, string>>();
            Assert.AreEqual(SaniTypes.FileNameCleanse, kvp.Key);
            Assert.AreEqual("FileNameCleanse:  Exception: Filename cannot be null or empty.", kvp.Value);

            sanitizer2.ClearSaniExceptions();

            try
            {
                //Test #7 - should track exception for bad file extensions
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("9999999999999999999999999", 50, false, null, true, true, true, true, true);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII(".", 50, false, null, true, true, true, true, true);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII(".pp.tx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII(".pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("?.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("a/abc.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("a\\abc.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("c:abc.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("c<abc.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("CON.pptx", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("test \"escape\".txt", 50, false, null, false, false, false, false, false);
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("C:\\My Folder <test>.\\", 50, false, null, false, false, false, false, false);

                //test restrictedList for Office files - set disallow to true
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("abc.docx", 50, false, null, false, false, true, false, false);
            }
            catch (SanitizerException)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            Assert.AreEqual(13, sanitizer2.SaniExceptions.Count);

            sanitizer2.ClearSaniExceptions();
        }

    }//end of class
}//end of namespace
