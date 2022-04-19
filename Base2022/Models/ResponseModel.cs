using BE_Base2022.Data.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BE_Base2022.Models
{
    public class ResponseModel
    {
        public ResponseModel(ResponseCode responseCode, string responseMessage, object dataSet)
        {
            ResponseCode = responseCode;
            ResponseMessage = responseMessage;
            DataSet = dataSet;
        }
        public ResponseCode ResponseCode { get; set; }
        public string ResponseMessage { get; set; }
        public object DataSet { get; set; }
    }
}
