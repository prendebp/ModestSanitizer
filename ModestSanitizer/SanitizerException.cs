using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
}
