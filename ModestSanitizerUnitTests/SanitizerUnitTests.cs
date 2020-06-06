using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using ModestSanitizer;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizerUnitTests
{
    [TestClass]
    public class SanitizerUnitTests
    {
        [TestMethod]
        public void Test_ReduceToValidMaxMinValue()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);

            DateTime? resultSQLServerDateTime = sanitizer.MinMax.ReduceToValidValue("1700-01-25 16:01:36.000", new DateTime(2020,1,1), new DateTime(1753,1,1), Utility.DateDataType.SQLServerDateTime, Utility.DateDelimiter.Dash, MinMax.DateFormat.SQLServer, false);

            Assert.AreEqual(new DateTime(1753, 1, 1, 0, 0, 0), resultSQLServerDateTime);

            //DateTime? resultNegativeSign = sanitizer.MinMax.ReduceToValidValue(tx);

            //Assert.AreEqual(-1220.5365M, resultNegativeSign);

            decimal? resultDollarSign = sanitizer.MinMax.ReduceToValidValue("-$100,000.00", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xCommaxDotx);

            Assert.AreEqual(-100000.00M, resultDollarSign);

            decimal? resultNegativeSign = sanitizer.MinMax.ReduceToValidValue("-1 220.5365$", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xSpacexDotx);

            Assert.AreEqual(-1220.5365M, resultNegativeSign);

            decimal? resultDotComma = sanitizer.MinMax.ReduceToValidValue("€120.000,99", 999999999999.99M, 0.00M, false, MinMax.CurrencySeparators.xDotxCommax);

            Assert.AreEqual(120000.99M, resultDotComma);

            decimal? resultSpaceComma = sanitizer.MinMax.ReduceToValidValue("€120 000,995", 999999999999.99M, 0.00M, false, MinMax.CurrencySeparators.xSpacexCommax);

            Assert.AreEqual(120000.995M, resultSpaceComma);

            decimal? resultSpace = sanitizer.MinMax.ReduceToValidValue("-20 000 $", 999999999999.99M, -100000.00M, true, MinMax.CurrencySeparators.xSpacexDotx);

            Assert.AreEqual(-20000M, resultSpace);

            decimal? resultSpace2 = sanitizer.MinMax.ReduceToValidValue("($20,000)", 999999999999.99M, -19000.00M, true);

            Assert.AreEqual(-19000M, resultSpace2);

            decimal? resultInvalidLeadZeroes = sanitizer.MinMax.ReduceToValidValue("$00,012.7", 999999999999.99M, 0.00M, true);

            Assert.AreEqual(12.7M, resultInvalidLeadZeroes);
  
            int ? result = sanitizer.MinMax.ReduceToValidValue("5", 4, 0);

            Assert.AreEqual(4, result);

            int? result2 = sanitizer.MinMax.ReduceToValidValue("4", 4, 0);

            Assert.AreEqual(4, result2);

            int? result3 = sanitizer.MinMax.ReduceToValidValue("3", 4, 0);

            Assert.AreEqual(3, result3);

            int? resultNull = sanitizer.MinMax.ReduceToValidValue(null, 50, 0);

            Assert.AreEqual(null, resultNull);

            int? result4 = sanitizer.MinMax.ReduceToValidValue("-51", 50, -50);

            Assert.AreEqual(-50, result4);

            int? result5 = sanitizer.MinMax.ReduceToValidValue("-49", 50, -50);

            Assert.AreEqual(-49, result5);

            bool wasExceptionThrown = false;
            try
            {
                sanitizer.MinMax.ReduceToValidValue("999999999999999999999999999999999", 50, -50);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            Sanitizer sanitizer2 = new Sanitizer(SaniApproach.TrackExceptionsInList, true);

            try
            {
                sanitizer2.MinMax.ReduceToValidValue("999999999999999999999999999999999", 50, -50);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            KeyValuePair<SaniTypes, string> kvp =  sanitizer2.SaniExceptions.Values.FirstOrDefault<KeyValuePair<SaniTypes, string>>();
            Assert.AreEqual(kvp.Key, SaniTypes.MinMax);
            Assert.AreEqual(kvp.Value, "999999999999999999999999999999999");


            bool? result6 = sanitizer.MinMax.ReduceToValidValue("false");

            Assert.AreEqual(false, result6);

            bool? result7 = sanitizer.MinMax.ReduceToValidValue(" ");

            Assert.AreEqual(null, result7);

            bool? result8 = sanitizer.MinMax.ReduceToValidValue("True");

            Assert.AreEqual(true, result8);

            wasExceptionThrown = false; //re-set flag

            try
            {
                bool? result9 = sanitizer.MinMax.ReduceToValidValue("1");
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            try
            {
                bool? result10 = sanitizer.MinMax.ReduceToValidValue("a bad value");
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(true, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag           
        }

        [TestMethod]
        public void Test_WhitelistEquals()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);
            bool wasExceptionThrown = false;
            string innerExceptionMsg = String.Empty;

            bool? result = sanitizer.Whitelist.EqualsUsingASCII("farside", "farside", 7);

            Assert.AreEqual(true, result);

            bool? result2 = sanitizer.Whitelist.EqualsIgnoreCaseUsingASCII("farside", "farSiDe", 7);

            Assert.AreEqual(true, result2);

            try 
            { 
                bool? result3 = sanitizer.Whitelist.EqualsUsingASCII("farside", "farSiDe", 7);

                Assert.AreEqual(false, result3);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck does NOT match whitelist value.", innerExceptionMsg);

            bool? result4 = sanitizer.Whitelist.EqualsUsingASCII("farside", "far", 3);

            Assert.AreEqual(true, result4);

            bool? result5 = sanitizer.Whitelist.EqualsIgnoreCaseUsingASCII("faRside", "faR", 3);

            Assert.AreEqual(true, result5);
        }

        [TestMethod]
        public void Test_BlacklistReview()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);
            bool wasExceptionThrown = false;
            string innerExceptionMsg = String.Empty;
                   
            try
            {
                //Hex value for 'javascript:alert(1337)'
                string hexValue = (@"\x6a\x61\x76\x61\x73\x63\x72\x69\x70\x74\x3a\x61\x6c\x65\x72\x74\x281337\x29");

                List<string> plainTextBlacklist = new List<string>();
                plainTextBlacklist.Add(@"javascript: alert(1337)");
                plainTextBlacklist.Add(@"javascript");
                plainTextBlacklist.Add(@"alert");

                bool checkForStandardHexBlacklistChars = false;

                bool? result1 = sanitizer.Blacklist.ReviewIgnoreCaseUsingASCII(hexValue, plainTextBlacklist, 225, checkForStandardHexBlacklistChars, false);

                Assert.AreEqual(false, result1); //no match since NOT checking for standard hex characters in the blacklist

                checkForStandardHexBlacklistChars = true;

                bool? result2 = sanitizer.Blacklist.ReviewIgnoreCaseUsingASCII(hexValue, plainTextBlacklist, 225, checkForStandardHexBlacklistChars, true);

                Assert.AreEqual(true, result2); //match true on hex char \x since bool to check for standard hex blacklist chars was set to true.
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck contains a blacklist value.", innerExceptionMsg);
                      
            wasExceptionThrown = false; //re-set flag
            innerExceptionMsg = String.Empty; //re-set msg

            try
            {
                string stringWithNullByte = @"myURL%00.biz";

                List<string> plainTextBlacklist = new List<string>();
                plainTextBlacklist.Add(@"myURL.biz");

                bool checkForCommonMaliciousChars = false;

                bool? result3 = sanitizer.Blacklist.ReviewIgnoreCaseUsingASCII(stringWithNullByte, plainTextBlacklist, 225, false, checkForCommonMaliciousChars);

                Assert.AreEqual(false, result3); //no match since NOT checking for common malicious characters in the blacklist

                checkForCommonMaliciousChars = true;

                bool? result4 = sanitizer.Blacklist.ReviewIgnoreCaseUsingASCII(stringWithNullByte, plainTextBlacklist, 225, true, checkForCommonMaliciousChars);

                Assert.AreEqual(true, result4); //match true on null byte %00 since bool to check for common malicious characters blacklist was set to true.
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
                innerExceptionMsg = se.InnerException.Message;
            }

            Assert.AreEqual(true, wasExceptionThrown);
            Assert.AreEqual("StringToCheck contains a common malicious character.", innerExceptionMsg);
        }

        [TestMethod]
        public void Test_TruncateToValidLength()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);
            String result = sanitizer.Truncate.TruncateToValidLength("testBigger", 4);

            Assert.AreEqual("test", result);

            String result2 = sanitizer.Truncate.TruncateToValidLength("test", 4);

            Assert.AreEqual("test", result2);

            String result3 = sanitizer.Truncate.TruncateToValidLength("testSmaller", 50);

            Assert.AreEqual("testSmaller", result3);

            String resultNull = sanitizer.Truncate.TruncateToValidLength(null, 50);

            Assert.AreEqual(null, resultNull);

            String resultStrEmpty = sanitizer.Truncate.TruncateToValidLength(String.Empty, 50);

            Assert.AreEqual(String.Empty, resultStrEmpty);
        }

        [TestMethod]
        public void Test_NormalizeUnicode()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);
            String result = sanitizer.NormalizeOrLimit.NormalizeUnicode("äiti");

            //Normalize to the nfkc format of Unicode
            Assert.AreEqual("\u00e4\u0069\u0074\u0069", result); //'äiti' in unicode characters of nfkc normalization form.

            //FYI, other types of Unicode formats: nfkd, nfc, and nfd
            //Assert.AreEqual("\u0061\u0308\u0069\u0074\u0069", result); //nfkd
            //Assert.AreEqual("\u00e4\u0069\u0074\u0069", unorm.nfc(str));
            //Assert.AreEqual("\u0061\u0308\u0069\u0074\u0069", unorm.nfd(str));

            //The idea here is to have a reliable whitelist (for comparison purposes)
            String potentiallyMaliciousString = "script";
            String normalizedString = sanitizer.NormalizeOrLimit.NormalizeUnicode(potentiallyMaliciousString); //normalize to nfkc format

            String whitelist = "\u0073\u0063\u0072\u0069\u0070\u0074"; //'script' in unicode characters of nfkc normalization form.

            Assert.AreEqual(whitelist, normalizedString); //compare
        }

        [TestMethod]
        public void Test_LimitToASCIIOnly()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);

            //Another approach to have a reliable whitelist (for comparison purposes)
            String potentiallyMaliciousString = "äiti®";

            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString);

            //Removes the accent from the 'a', but removes the copyright symbol altogether
            Assert.AreEqual("aiti", stringLimitedToLetterlikeChars); //compare

            String potentiallyMaliciousString2 = @"&euml;,ä,&ccedil;,!@#$%^%&*(*)__+~!`';,./<>\|}{-=/*-+.,./?";

            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars2 = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString2);

            //Removes the accent from the 'a'
            Assert.AreEqual(@"&euml;,a,&ccedil;,!@#$%^%&*(*)__+~!`';,./<>\|}{-=/*-+.,./?", stringLimitedToLetterlikeChars2); //compare
             
            String potentiallyMaliciousString3 = "U, Ù, Ú, Û, ñ, Ü, Ů, ç, Ő";
                                                     
            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars3 = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString3);

            //Removes the accent marks from the unicode characters U, n, c O
            Assert.AreEqual("U, U, U, U, n, U, U, c, O", stringLimitedToLetterlikeChars3); //compare

            String potentiallyMaliciousString4 = "È,É,Ê,Ë,Û,Ù,Ï,Î,À,Â,Ô,è,é,ê,ë,û,ù,ï,î,à,â,ô";

            String stringLimitedToLetterlikeChars4 = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString4);

            //Removes the accent marks from the unicode characters E, U, I, A, O including lower case versions
            Assert.AreEqual("E,E,E,E,U,U,I,I,A,A,O,e,e,e,e,u,u,i,i,a,a,o", stringLimitedToLetterlikeChars4); //compare
        }

        [TestMethod]
        public void Test_SanitizeViaRegexUsingASCII()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions, true);
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

            Sanitizer sanitizer2 = new Sanitizer(SaniApproach.TrackExceptionsInList, true);

            try
            {
                //Test #6 - should track exception for no file extension
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("999999999999999999999999999999999", 50, false, null, true, true, true, true, true);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            KeyValuePair<SaniTypes, string> kvp = sanitizer2.SaniExceptions.Values.FirstOrDefault<KeyValuePair<SaniTypes, string>>();
            Assert.AreEqual(kvp.Key, SaniTypes.FileNameCleanse);
            Assert.AreEqual(kvp.Value, "Filename: 999999999999999 Exception: Filename does NOT contain at least one dot character.");

            sanitizer2.SaniExceptions.Clear();

            try
            {
                //Test #7 - should track exception for bad file extensions
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

                //test blacklist for Office files - set disallow to true
                sanitizer2.FileNameCleanse.SanitizeViaRegexUsingASCII("abc.docx", 50, false, null, false, false, true, false, false);
            }
            catch (SanitizerException se)
            {
                wasExceptionThrown = true;
            }

            Assert.AreEqual(false, wasExceptionThrown);

            wasExceptionThrown = false; //re-set flag

            Assert.AreEqual(12, sanitizer2.SaniExceptions.Count);
        }

    }//end of class
}//end of namespace
