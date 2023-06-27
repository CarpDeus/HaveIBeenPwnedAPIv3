using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using HaveIBeenPwnedAPI;

namespace HaveIBeenPwnedApiUnitTests
{
    [TestClass]
    public class PasteUnitTests
    {
        // This needs set to run tests
        readonly string apiKey = "";
        readonly string userAgent = "azure-architect.com-UnitTests";

        [TestMethod]
        public void PastesFound()
        {
            HaveIBeenPwnedPastes checkPastes = HaveIBeenPwnedApiV3.CheckPastes(apiKey, userAgent, "jfinsel@azure-architect.com");
            Assert.IsTrue(checkPastes.Count > 0);
        }

        [TestMethod]
        public void NoPastesFound()
        {
            HaveIBeenPwnedPastes checkPastes = HaveIBeenPwnedApiV3.CheckPastes(apiKey, userAgent, $"{Guid.NewGuid()}@azure-architect.com");
            Assert.AreEqual(checkPastes.Count, 0);
        }
    }
}