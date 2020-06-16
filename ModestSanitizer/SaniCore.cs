using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static ModestSanitizer.Sanitizer;

namespace ModestSanitizer
{
    public class SaniCore : ISaniCore
    {
        public enum Approach
        {
            None = 0,
            TrackExceptionsInList = 1,
            ThrowExceptions = 2
        }

        public bool CompileRegex { get; set; }

        public Truncate Truncate { get; set; }
        public RestrictedList RestrictedList { get; set; }
        public MinMax MinMax { get; set; }
        public NormalizeOrLimit NormalizeOrLimit { get; set; }
        public FileNameCleanse FileNameCleanse { get; set; }
        public AllowedList AllowedList { get; set; }

        public Approach SanitizerApproach { get; set; }
        public Dictionary<Guid, KeyValuePair<SaniTypes, string>> SaniExceptions { get; set; }

        public SaniCore() { }

    }//end of class
}//end of namespace
