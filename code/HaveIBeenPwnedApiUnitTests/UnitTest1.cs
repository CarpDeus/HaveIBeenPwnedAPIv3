using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Net.Http;
using HaveIBeenPwnedAPI;

namespace HaveIBeenPwnedApiUnitTests
{
    [TestClass]
    public class UnitTest1
    {
        //This needs set to run tests
        readonly string apiKey = "";
        readonly string userAgent = "azure-architect.com-UnitTests";
        
        [TestMethod]
        public void PasswordCheckFound()
        {
            long x = HaveIBeenPwnedApiV3.PasswordCheck(apiKey, userAgent, "123456");
            Assert.IsTrue(x > 0);
        }

        [TestMethod]
        public void PasswordCheckNotFound()
        {
            long x = HaveIBeenPwnedApiV3.PasswordCheck(apiKey, userAgent, Guid.NewGuid().ToString());
            Assert.AreEqual(x , 0);
        }

        [TestMethod]
        [ExpectedException(typeof(HttpRequestException), "User Agent Not supplied")]
        public void PasswordCheckNoUserAgentSupplied()
        {
            
            HaveIBeenPwnedApiV3.PasswordCheck(apiKey, "", Guid.NewGuid().ToString());
        }

        
        

    }
}
