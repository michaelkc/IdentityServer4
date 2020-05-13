using System.Collections.Generic;
using System.Security.Claims;

namespace TokenExchange.IntegrationTests.Common
{
    internal class ClaimSet : List<KeyValuePair<string, string>>
    {
        // A dictionary allowing multiple keys, which supports collection initializer syntax
        public void Add(string key, string value)
        {
            Add(new KeyValuePair<string, string>(key, value));
        }

        public static ClaimSet FromClaims(IEnumerable<Claim> typedClaims)
        {
            var cs = new ClaimSet();
            foreach (var c in typedClaims)
            {
                cs.Add(c.Type, c.Value);
            }

            return cs;
        }
    }
}
