using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  FileNameCleanse = 6
    ///  SanitizeViaRegexUsingASCII
    //   Why? To assist with cleaning filenames of invalid or malicious characters such as null bytes or characters that reverse order to Right-To-Left.
    /// </summary>
    public class FileNameCleanse
    {
        public Truncate Truncate { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public FileNameCleanse()
        {
        }

        public FileNameCleanse(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public FileNameCleanse(Truncate truncate, NormalizeOrLimit normalizeOrLimit, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            NormalizeOrLimit = normalizeOrLimit;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// Sanitize FileName Via Regex. Disallow more than one dot in the filename. 
        /// SOURCE: https://stackoverflow.com/questions/11794144/regular-expression-for-valid-filename
        /// SOURCE: https://stackoverflow.com/questions/6730009/validate-a-file-name-on-windows
        /// SOURCE: https://stackoverflow.com/questions/62771/how-do-i-check-if-a-given-string-is-a-legal-valid-file-name-under-windows#62855
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public string SanitizeViaRegexUsingASCII(string filename, int maxLength, bool disallowMoreThanOneDot)
        {
            string tmpResult = String.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(filename))
                {
                    tmpResult = filename;
                }
                else
                {
                    tmpResult = Truncate.TruncateToValidLength(filename, maxLength);

                    if (ContainsMaliciousCharacters(ref tmpResult))
                    {
                        throw new Exception("Filename contains potentially malicious characters.");
                    }

                 
                        char dot = '.';
                        int count = 0;
                        foreach (char letter in tmpResult)
                            if (letter == dot) count++;

                    if (disallowMoreThanOneDot)
                    {
                        if (count > 1)
                        {
                            throw new Exception("Filename contains more than one dot character.");
                        }
                    }

                    if (count == 0)
                    {
                        throw new Exception("Filename does NOT contain at least one dot character.");
                    }

                    tmpResult = NormalizeOrLimit.LimitToASCIIOnly(tmpResult);

                    string regex2 = @"^(?!^(PRN|AUX|CLOCK\$|NUL|CON|COM\d|LPT\d|\..*)(\..+)?$)[^\x00-\x1f\\?*:\"";|\/]+[^*\x00-\x1F\ .]$";
                    bool matchOnWindows = Regex.IsMatch(tmpResult, regex2,  RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                    if (!matchOnWindows)
                    {
                        throw new Exception("Filename is NOT a valid Windows filename.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException("Error sanitizing via Regex using ASCII: ", tmpResult, ex);
            }

            return tmpResult;
        }

        private static bool ContainsMaliciousCharacters(ref string tmpResult)
        {
            //Prevent null bytes % 00 injected to terminate the filename: secret.doc % 00.pdf
            //Also, assure it doesn't contain U+202E or U+200F characters meant to manipulate Left-To-Right or Right-To-Left order

            int initialLength = tmpResult.Length;
            tmpResult = tmpResult.Replace("\0", string.Empty);
            tmpResult = tmpResult.Replace("\u00A0", string.Empty);
            tmpResult = tmpResult.Replace("\u0000", string.Empty);
            tmpResult = tmpResult.Replace("\u202E", string.Empty);
            tmpResult = tmpResult.Replace("\u200F", string.Empty);
            tmpResult = tmpResult.Replace("% 00", string.Empty);
            tmpResult = tmpResult.Replace("%00", string.Empty);
            int finalLength = tmpResult.Length;

            return (finalLength< initialLength);
        }

        private void TrackOrThrowException(string msg, string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 15); //allow a few more characters than normal for troubleshooting filenames

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                string exceptionMsg = String.Empty;
                if (ex != null && ex.Message!= null)
                {
                    exceptionMsg = ex.Message;
                }

                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.FileNameCleanse, "Filename: " + exceptionValue + " Exception: " + exceptionMsg));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
