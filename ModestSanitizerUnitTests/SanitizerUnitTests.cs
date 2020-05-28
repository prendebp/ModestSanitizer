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
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);
            int? result = sanitizer.MinMax.ReduceToValidValue("5", 4, 0);

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

            Sanitizer sanitizer2 = new Sanitizer(SaniApproach.TrackExceptionsInList);

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
            Assert.AreEqual(kvp.Value, "99999");
        }

        [TestMethod]
        public void Test_TruncateToValidLength()
        {
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);
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
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);
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
            Sanitizer sanitizer = new Sanitizer(SaniApproach.ThrowExceptions);

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

            //Removes the accent from the 'a', but removes the copyright symbol altogether
            Assert.AreEqual("U, U, U, U, n, U, U, c, O", stringLimitedToLetterlikeChars3); //compare

            String potentiallyMaliciousString4 = "È,É,Ê,Ë,Û,Ù,Ï,Î,À,Â,Ô,è,é,ê,ë,û,ù,ï,î,à,â,ô";

            //The idea here is to limit the string of UTF-8 characters to 
            //just the subset of unicode chars that "matches" ASCII characters.
            String stringLimitedToLetterlikeChars4 = sanitizer.NormalizeOrLimit.LimitToASCIIOnly(potentiallyMaliciousString4);

            //Removes the accent marks
            Assert.AreEqual("E,E,E,E,U,U,I,I,A,A,O,e,e,e,e,u,u,i,i,a,a,o", stringLimitedToLetterlikeChars4); //compare
        }
    }
}
