using Microsoft.AspNetCore.DataProtection;

namespace PassManApp.Services
{
    public class PasswordService
    {
        private readonly IDataProtector _protector;

        public PasswordService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("PasswordProtector");
        }

        public string EncryptPassword(string plainTextPassword)
        {
            return _protector.Protect(plainTextPassword);
        }

        public string DecryptPassword(string encryptedPassword)
        {
            return _protector.Unprotect(encryptedPassword);
        }
    }

}
