using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace App.Struct
{
    class Sale
    {
        [JsonProperty("price")]
        public UInt32 Price { get; set; }

        [JsonProperty("sale_time")]
        public UInt32 SaleTime { get; set; }

        [JsonProperty("quantity")]
        public int Quantity { get; set; }

        [JsonProperty("hq")]
        public bool Hq { get; set; }

        [JsonProperty("buyer")]
        public string Buyer { get; set; }
    }
}
