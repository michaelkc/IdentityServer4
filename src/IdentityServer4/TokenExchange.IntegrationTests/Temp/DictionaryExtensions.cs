using System;
using System.Collections.Generic;
using TokenExchange.IntegrationTests.Clients;

namespace TokenExchange.IntegrationTests.Temp
{
    internal static class DictionaryExtensions
    {
        public static void AddOptional(this IDictionary<string, string> parameters, string key, string value)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
        }

        public static void AddRequired(this IDictionary<string, string> parameters, string key, string value, bool allowEmpty = false)
        {
            if (parameters == null) throw new ArgumentNullException(nameof(parameters));

            if (value.IsPresent())
            {
                if (parameters.ContainsKey(key))
                {
                    throw new InvalidOperationException($"Duplicate parameter: {key}");
                }
                else
                {
                    parameters.Add(key, value);
                }
            }
            else
            {
                if (allowEmpty)
                {
                    parameters.Add(key, "");
                }
                else
                {
                    throw new ArgumentException("Parameter is required", key);
                }
            }
        }
    }
}