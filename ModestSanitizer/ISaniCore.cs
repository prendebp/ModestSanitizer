using System;
using System.Collections.Generic;

namespace ModestSanitizer
{
    public interface ISaniCore
    {
        AllowedList AllowedList { get; set; }
        bool CompileRegex { get; set; }
        FileNameCleanse FileNameCleanse { get; set; }
        MinMax MinMax { get; set; }
        NormalizeOrLimit NormalizeOrLimit { get; set; }
        RestrictedList RestrictedList { get; set; }
        Dictionary<Guid, KeyValuePair<Sanitizer.SaniTypes, string>> SaniExceptions { get; set; }
        SaniCore.Approach SanitizerApproach { get; set; }
        Truncate Truncate { get; set; }
    }
}