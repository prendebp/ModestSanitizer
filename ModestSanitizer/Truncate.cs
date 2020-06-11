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
        public Approach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public Truncate()
        {
        }

        public Truncate(Approach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public Truncate(Approach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            SaniExceptions = saniExceptions;
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
                    tmpResult = strToClean;
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
                TrackOrThrowException(strToClean, ex);
            }
            return tmpResult;
        }            
        
        private void TrackOrThrowException(string valToClean, Exception ex)
        {
            string exceptionValue = ToValidLength(valToClean, 5);

            if (SanitizerApproach == Approach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.Truncate, exceptionValue));
            }
            else
            {
                throw new SanitizerException("Error truncating to valid length: " + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
