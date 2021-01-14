using System;
using System.IO;
using System.Text;
using System.Activities;
using System.ComponentModel;
using System.Security.Cryptography;

namespace AES256
{
    public class AESEncrypt : CodeActivity
    {
        [Category("Input")]
        [RequiredArgument]
        public InArgument<string> Key { get; set; }

        [Category("Input")]
        public InArgument<string> IV { get; set; }

        [Category("Input")]
        public InArgument<string> PlainText { get; set; }

        [Category("Output")]
        public OutArgument<string> CipherText { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            var key = Key.Get(context);
            var iv = IV.Get(context);
            var plainText = PlainText.Get(context);

            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");

            byte[] encrypted;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(iv));
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }

            var result = Convert.ToBase64String(encrypted);
            CipherText.Set(context, result);
        }
    }

    public class AESDecrypt : CodeActivity
    {
        [Category("Input")]
        [RequiredArgument]
        public InArgument<string> Key { get; set; }

        [Category("Input")]
        public InArgument<string> IV { get; set; }

        [Category("Input")]
        public InArgument<string> CipherText { get; set; }

        [Category("Output")]
        public OutArgument<string> PlainText { get; set; }

        protected override void Execute(CodeActivityContext context)
        {
            var key = Key.Get(context);
            var iv = IV.Get(context);
            var cipherText = CipherText.Get(context);

            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");

            string plaintext = null;
            using (AesManaged aes = new AesManaged())
            {
                ICryptoTransform decryptor = aes.CreateDecryptor(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(iv));
                using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(cipherText)))
                {
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            PlainText.Set(context, plaintext);
        }
    }
}
