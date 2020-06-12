using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using static ModestSanitizer.SaniCore;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    [Serializable]
    public class SanitizerException : Exception
    {
        public SanitizerException()
        { }

        public SanitizerException(string message)
            : base(message)
        { }

        public SanitizerException(string message, Exception innerException)
            : base(message, innerException)
        { }
    }

    public static class SaniExceptionHandler
    {
        public static void TrackOrThrowException(int truncateLength, SaniTypes saniType, SaniCore saniCore, string msgTitle, string msg, string strToClean, Exception ex) //"Filename: "
        {
            string exceptionValue = String.Empty;

            //Truncate length to protect the log
            if (string.IsNullOrWhiteSpace(strToClean))
            {
                exceptionValue = String.Empty;
            }
            else
            {
                if (strToClean.Length >= truncateLength)
                {
                    exceptionValue = strToClean.Substring(0, truncateLength);
                }
                else
                {
                    exceptionValue = strToClean;
                }
            }

            //Limit to ASCII Only and remove possible malicious characters - apply a limited whitelist to protect the log
            exceptionValue = (new string(exceptionValue.ToCharArray().Where(c => ((32 <= (int)c && (int)c <= 126)
            && ((int)c != 37) //% sign - could be part of hexadecimal character
            && ((int)c != 47) //forward slash - could be part of a malicious URL
            && ((int)c != 64) //@ symbol - could be part of a malicious email address
            && ((int)c != 92) //backslash - could be part of a null byte or unicode bypass character
            )).ToArray()));

            if (saniCore.SanitizerApproach == Approach.TrackExceptionsInList)
            {
                string exceptionMsg = String.Empty;
                if (ex != null && ex.Message != null)
                {
                    exceptionMsg = ex.Message;
                }

                saniCore.SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(saniType, msgTitle + exceptionValue + " Exception: " + exceptionMsg));
            }
            else
            {
                throw new SanitizerException(msg + (exceptionValue ?? String.Empty), ex);
            }
        }
    }//end of class
}//end of namespace
