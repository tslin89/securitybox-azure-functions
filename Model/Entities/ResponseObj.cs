using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityBoxFunctions.Library;

namespace SecurityBoxFunctions.Model.Entities
{
    public class ResponseObject
    {
        public string transactionID { get; set; }
        public int Status { get; set; }
        public string Message { get; set; }
        public object Data { get; set; }

        public ResponseObject()
        {
            transactionID = Guid.NewGuid().ToString();
            Status = (int)CommonEnum.ResponseStatus.Success;
            Message = "success";
        }
    }
}