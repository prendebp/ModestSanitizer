using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  Truncate = 2
    ///  TruncateToValidLength (e.g. max length of a string)
    ///  Why? To protect against malicious hackers passing-in gigabyte-length strings.
    ///  </summary>
    public class Truncate
    {
        public SaniCore SaniCore { get; set; }

        private int TruncateLength { get; set; }
        private SaniTypes SaniType { get; set; }

        public Truncate(SaniCore saniCore)
        {
            SaniCore = saniCore;

            TruncateLength = 10;
            SaniType = SaniTypes.Truncate;
        }

        /// <summary>
        /// TruncateToValidLength -  max length of a string
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public string ToValidLength(string strToClean, int strMaxLength)
        {
            string tmpResult = String.Empty;

            try
            {
                if (string.IsNullOrWhiteSpace(strToClean))
                {
                    tmpResult = null; //Always return null. Protects against a gigabyte of whitespace!!!
                }
                else
                {
                    if (strToClean.Length >= strMaxLength)
                    {
                        tmpResult = strToClean.Substring(0, strMaxLength);
                    }
                    else
                    {
                        tmpResult = strToClean;
                    }
                }
            }
            catch (Exception ex)
            {
                SaniExceptionHandler.TrackOrThrowException(TruncateLength, SaniType, SaniCore, "Truncate: ", "Error truncating to valid length: ", strToClean, ex);
            }
            return tmpResult;
        } 

    }//end of class
}//end of namespace
