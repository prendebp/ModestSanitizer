using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    /// <summary>
    ///  MinMax = 1
    ///  ReduceToValidValue (e.g. max value of a number)
    //   Why? To protect against buffer overflow attacks, e.g. if using unsafe keyword: https://stackoverflow.com/questions/9343665/are-buffer-overflow-exploits-possible-in-c
    /// </summary>
    public class MinMax
    {
        public Truncate Truncate { get; set; }
        public SaniApproach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public MinMax()
        {
        }

        public MinMax(SaniApproach sanitizerApproach)
        {
            SanitizerApproach = sanitizerApproach;
        }

        public MinMax(Truncate truncate, SaniApproach sanitizerApproach, Dictionary<Guid, KeyValuePair<SaniTypes, string>> saniExceptions) : this(sanitizerApproach)
        {
            Truncate = truncate;
            SaniExceptions = saniExceptions;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable long (SQL Server BigInt)
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>         
        public long? ReduceToValidValue(string longToClean, long longMaxValue, long longMinValue)
        {
            long? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(longToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    long value;
                    bool isSuccess = long.TryParse(longToClean, out value);
                    if (isSuccess)
                    {
                        if (value < 0)
                        {
                            if (Math.Min(value, longMinValue) == longMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = longMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, longMaxValue) == longMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = longMaxValue;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(longToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable decimal
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>         
        public decimal? ReduceToValidValue(string decimalToClean, decimal decimalMaxValue, decimal decimalMinValue)
        {
            decimal? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(decimalToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    decimal value;
                    bool isSuccess = decimal.TryParse(decimalToClean, out value);
                    if (isSuccess)
                    {
                        if (value < 0)
                        {
                            if (Math.Min(value, decimalMinValue) == decimalMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = decimalMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, decimalMaxValue) == decimalMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = decimalMaxValue;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(decimalToClean, ex);
            }
            return tmpResult;
        }

        /// <summary>
        /// ReduceToValidMaxMinValues - enforce max and min value of a nullable integer
        /// SOURCE: https://stackoverflow.com/questions/3115678/converting-string-to-int-using-c-sharp
        /// </summary>
        /// <param name="strToClean"></param>
        /// <returns></returns>   
        public int? ReduceToValidValue(string intToClean, int intMaxValue, int intMinValue)
        {
            int? tmpResult = 0;

            try
            {
                if (String.IsNullOrWhiteSpace(intToClean))
                {
                    tmpResult = null;
                }
                else
                {
                    int value;
                    bool isSuccess = int.TryParse(intToClean, out value);
                    if (isSuccess)
                    {
                        if (value < 0)
                        {
                            if (Math.Min(value, intMinValue) == intMinValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = intMinValue;
                            }
                        }
                        else
                        {
                            if (Math.Max(value, intMaxValue) == intMaxValue)
                            {
                                tmpResult = value;
                            }
                            else
                            {
                                tmpResult = intMaxValue;
                            }
                        }
                    }
                    else
                    {
                        throw new Exception("Parse Failure.");
                    }
                }
            }
            catch (Exception ex)
            {
                TrackOrThrowException(intToClean, ex);
            }
            return tmpResult;
        }
        
        private void TrackOrThrowException(string valToClean, Exception ex)
        {
            string exceptionValue = Truncate.TruncateToValidLength(valToClean, 5);

            if (SanitizerApproach == SaniApproach.TrackExceptionsInList)
            {
                SaniExceptions.Add(Guid.NewGuid(), new KeyValuePair<SaniTypes, string>(SaniTypes.MinMax, exceptionValue));
            }
            else
            {
                throw new SanitizerException("Error reduce to valid MinMax value: " + exceptionValue, ex);
            }
        }
    }//end of class
}//end of namespace
