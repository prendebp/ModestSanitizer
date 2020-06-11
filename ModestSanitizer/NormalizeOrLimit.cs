using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  NormalizeOrLimit = 3
    ///  NormalizeUnicode or ToASCIIOnly
    //   Why? To assist with safe whitelisting
    /// </summary>
    public class NormalizeOrLimit
    {
        private Truncate Truncate { get; set; }
        public Approach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public NormalizeOrLimit()
        {
        }

        public NormalizeOrLimit(Approach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public NormalizeOrLimit(Truncate truncate, Approach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// Normalize Unicode for if you are planning to compare against a Unicode Whitelist (so you know which Normalization Form to use.)
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public string NormalizeUnicode(string strToClean)
        {
            string tmpResult = String.Empty;

            try
            {
                //SOURCE: https://stackoverflow.com/questions/15683717/unicode-to-ascii-conversion-mapping

                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = strToClean.Normalize(NormalizationForm.FormKC);

                    //This will retain diacritic characters after normalization.
                    tmpResult = new string(tmpResult.Where(c =>
                    {
                        UnicodeCategory category = CharUnicodeInfo.GetUnicodeCategory(c);
                        return category != UnicodeCategory.NonSpacingMark;
                    }).ToArray());
                }

            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error normalizing unicode: ", strToClean, ex);
            }

            return tmpResult;
        }


        /// <summary>
        /// Limit a Unicode string to just the limited subset of ASCII-compatible characters.
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public string ToASCIIOnly(string strToClean)
        {
            string tmpResult = String.Empty;
            bool removeAccents = true;

            try
            {

                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = strToClean.Normalize(NormalizationForm.FormKC);

                    //SOURCES:
                    //https://stackoverflow.com/questions/1008802/converting-symbols-accent-letters-to-english-alphabet
                    //http://www.codecodex.com/wiki/Unaccent_letters
                    //http://www.unicode.org/Public/security/latest/confusables.txt
                    //https://stackoverflow.com/questions/4846365/find-characters-that-are-similar-glyphically-in-unicode

                    if (removeAccents)
                    {
                        string PLAIN_ASCII =
                            "AaEeIiOoUu"    // grave ` (U+0060)
                          + "AaEeIiOoUuYy"  // acute ´ (U+00B4)
                          + "AaEeIiOoUuYy"  // circumflex ^ (U+005E)
                          + "AaOoNn"        // tilde ~ (U+007E) [Most frequent in Spanish such as "español".]
                          + "AaEeIiOoUuYy"  // diaeresis or umlaut ̈	 (U+0308)
                          + "AaUu"          // ring ̊  (U+030A) [Most frequent Danish or Swedish Å, but also potentially Ů in Czech.]
                          + "Cc"            // cedilla ̧  (U+00B8) [Most frequent character with cedilla is "ç" such as in "façade".]
                          + "OoUu";         // double acute ̋   (U+030B) [Most frequent in Hungarian for Ő and Ű.]

                        //For example, handles: Ù, Ú, Û, ñ, Ü, Ů, ç, Ű

                        //TODO: Add support for the following: Ū, Ŭ

                        //Does NOT currently support the following diacritical chars: Ư, Ǔ, Ǖ, Ǘ, Ǚ, Ǜ, Ủ, Ứ, Ừ, Ử, Ữ, Ự";

                        string UNICODE =
                          "\u00C0\u00E0\u00C8\u00E8\u00CC\u00EC\u00D2\u00F2\u00D9\u00F9"
                         + "\u00C1\u00E1\u00C9\u00E9\u00CD\u00ED\u00D3\u00F3\u00DA\u00FA\u00DD\u00FD"
                         + "\u00C2\u00E2\u00CA\u00EA\u00CE\u00EE\u00D4\u00F4\u00DB\u00FB\u0176\u0177"
                         + "\u00C3\u00E3\u00D5\u00F5\u00D1\u00F1"
                         + "\u00C4\u00E4\u00CB\u00EB\u00CF\u00EF\u00D6\u00F6\u00DC\u00FC\u0178\u00FF"
                         + "\u00C5\u00E5\u016E\u016F"
                         + "\u00C7\u00E7"
                         + "\u0150\u0151\u0170\u0171"
                         ;

                        // remove accentuated from a string and replace with ascii equivalent
                        StringBuilder sb = new StringBuilder();

                        int n = tmpResult.Length;
                        for (int i = 0; i < n; i++)
                        {
                            char c = tmpResult.ToCharArray()[i];
                            int pos = UNICODE.IndexOf(c);
                            if (pos > -1)
                            {
                                sb.Append(PLAIN_ASCII.ToCharArray()[pos]);
                            }
                            else
                            {
                                sb.Append(c);
                            }
                        }
                        tmpResult = sb.ToString();

                        //THIS WILL LIMIT TO A SUBSET OF ASCII CHARACTERS. THIS WILL REMOVE ANY DIACRITIC, TABS, NEW LINE CHARACTERS!!
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => (32 <= (int)c && (int)c <= 126)).ToArray()));
                    }
                }

            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error limiting unicode to ASCII: ", strToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// Limit a Unicode string to just the limited subset of ASCII-compatible numbers, aka Latin numbers.
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public string ToASCIINumbersOnly(string strToClean, bool allowSpaces, bool allowParens, bool allowNegativeSign, bool allowCommaAndDot)
        {
            string tmpResult = String.Empty;

            try
            {

                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = ToASCIIOnly(strToClean);
                 
                    //limit further
                    tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48<= (int)c && (int)c <= 57) 
                    || (allowSpaces?((int)c==32):false) //32 = space
                    || (allowParens ? (((int)c == 40)|| ((int)c == 41)) : false)//40 and 41 = parens
                    || (allowCommaAndDot ? ((int)c == 44) : false) //44 = ,
                    || (allowNegativeSign ? ((int)c == 45) : false) //45 = dash 
                    || (allowCommaAndDot ? ((int)c == 46) : false) //46 = dot 
               
                    )).ToArray()));                    
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error limiting unicode to ASCII Numbers Only: ", strToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// Limit a Unicode string to just the limited subset of ASCII-compatible date times only, aka Latin numbers with date and time delimiters.
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public string ToASCIIDateTimesOnly(string strToClean, DateUtil.Delim delimiter, DateUtil.DataType dateDataType, bool allowAMandPM)
        {
            string tmpResult = String.Empty;
            if (dateDataType == DateUtil.DataType.SQLServerDateTime)
            {
                dateDataType = DateUtil.DataType.DateTimeWithMilliseconds; //retain colon and space
            }

            try
            {

                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = strToClean;
                }
                else
                {
                    tmpResult = Truncate.ToValidLength(strToClean, 33);
                    tmpResult = tmpResult.Normalize(NormalizationForm.FormKC);//just to be extra safe
                  
                    //Example 12-8-2015 15:15
                    if (delimiter == DateUtil.Delim.Dash && !(delimiter == DateUtil.Delim.UTCWithDelimiters || delimiter == DateUtil.Delim.UTCWithoutDelimiters || delimiter == DateUtil.Delim.UTCWithDelimitersAndZone))
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57) //Latin numbers
                          || ((int)c == 45) //45 = dash
                          || (allowAMandPM ? (((int)c == 65) || ((int)c == 77) || ((int)c == 80) || ((int)c == 97) || ((int)c == 109) || ((int)c == 112)) : false) //65 = A , 77 = M, 80 = P, 97 = a, 109 = m, 112 = p
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 32) : false) //32 = space
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 58) : false) //58 = colon
                          || ((dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 46) : false) //46 = dot
                        )).ToArray()));
                    }

                    //Example 12.8.2015 15:15
                    if (delimiter == DateUtil.Delim.Dot && !(delimiter == DateUtil.Delim.UTCWithDelimiters || delimiter == DateUtil.Delim.UTCWithoutDelimiters || delimiter == DateUtil.Delim.UTCWithDelimitersAndZone)) 
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57)
                          || ((int)c == 46) //46 = dot 
                          || (allowAMandPM ? (((int)c == 65) || ((int)c == 77) || ((int)c == 80) || ((int)c == 97) || ((int)c == 109) || ((int)c == 112)) : false) //65 = A , 77 = M, 80 = P, 97 = a, 109 = m, 112 = p
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 32) : false) //32 = space
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 58) : false) //58 = colon
                        )).ToArray()));
                    }

                    //Example 12/8/2015 15:15
                    if (delimiter == DateUtil.Delim.ForwardSlash && !(delimiter == DateUtil.Delim.UTCWithDelimiters || delimiter == DateUtil.Delim.UTCWithoutDelimiters || delimiter == DateUtil.Delim.UTCWithDelimitersAndZone)) 
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57)
                          || ((int)c == 47) //47 = forward slash 
                          || (allowAMandPM ? (((int)c == 65) || ((int)c == 77) || ((int)c == 80) || ((int)c == 97) || ((int)c == 109) || ((int)c == 112)) : false) //65 = A , 77 = M, 80 = P, 97 = a, 109 = m, 112 = p
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 32) : false) //32 = space
                          || ((dateDataType == DateUtil.DataType.DateTime || dateDataType == DateUtil.DataType.DateTimeWithSeconds || dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 58) : false) //58 = colon
                          || ((dateDataType == DateUtil.DataType.DateTimeWithMilliseconds) ? ((int)c == 46) : false) //46 = dot             
                        )).ToArray()));
                    }

                    if (delimiter == DateUtil.Delim.UTCWithoutDelimiters) //yyyyMMdd'T'HHmmss.SSSZ
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57) //Latin numbers
                        || ((int)c == 46) //46 = dot
                        || (((int)c == 84) || ((int)c == 90) || ((int)c == 32)) //84 = T, 90 = Z, 32 = space
                        )).ToArray()));
                    }
                                         
                    if (delimiter == DateUtil.Delim.UTCWithDelimitersAndZone) //yyyy-MM-dd'T'HH:mm:ssK EXAMPLE: 2020-06-10T22:03:15-05:00
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57) //Latin numbers
                        || ((int)c == 45) //45 = dash and minus sign
                        || ((int)c == 58) //58 = colon
                        || ((int)c == 43) //43 = plus sign
                        || (((int)c == 84) || ((int)c == 90) || ((int)c == 32)) //84 = T, 90 = Z, 32 = space
                        )).ToArray()));
                    }

                    if (delimiter == DateUtil.Delim.UTCWithDelimiters) //yyyy-MM-dd'T'HH:mm:ss.SSSZZ  EXAMPLE: 2014-08-29T06:44:03Z
                    {
                        tmpResult = (new string(tmpResult.ToCharArray().Where(c => ((48 <= (int)c && (int)c <= 57) //Latin numbers
                        || ((int)c == 45) //45 = dash 
                        || ((int)c == 58) //58 = colon
                        || (((int)c == 84) || ((int)c == 90) || ((int)c == 32)) //84 = T, 90 = Z, 32 = space
                        )).ToArray()));
                    }

                    //TODO: support 1995-07-14T13:05:00.0000000-03:00 ?!?
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error limiting unicode to ASCII DateTimes Only: ", strToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// Detect ill-formed UTF-8 sequences in raw bytes. 
        /// </summary>
        /// <param name="rawData"></param>
        /// <returns></returns>
        public bool DetectMalformedUTF8Bytes(byte[] rawData)
        {
            UTF8Encoding encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: false);
            return encoding.GetString(rawData).Contains("\uFFFD"); //will replace ill-formed data with U+FFFD REPLACEMENT CHARACTER ('�')
        }
                
        /// <summary>
        /// Detect ill-formed ASCII characters in raw bytes. 
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>
        public bool DetectMalformedASCII(byte[] rawData)
        {
            ASCIIEncoding encoding = new ASCIIEncoding();
            return encoding.GetString(rawData).Contains("?"); //will replace ill-formed data with '?'
        }

        private void TrackOrThrowException(string msg, string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.ToValidLength(valToClean, 5);

            if (SanitizerApproach == Approach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.NormalizeOrLimit, exceptionValue));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
