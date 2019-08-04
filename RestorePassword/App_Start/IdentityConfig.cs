using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using RestorePassword.Models;
using System.Net.Mail;
using System.IO;
using System.Security.Cryptography;

namespace RestorePassword
{
    public class EmailService : IIdentityMessageService
    {
        public static String Decrypt(String decryptstr)
        {
            string decrypted = string.Empty;
            try
            {
                byte[] data = System.Convert.FromBase64String(decryptstr);
                byte[] rgbKey = System.Text.ASCIIEncoding.ASCII.GetBytes("vY7q-3Os");
                byte[] rgbIV = System.Text.ASCIIEncoding.ASCII.GetBytes("_1pCq7Yw");

                MemoryStream memoryStream = new MemoryStream(data.Length);
                DESCryptoServiceProvider desCryptoServiceProvider = new DESCryptoServiceProvider();
                ICryptoTransform x = desCryptoServiceProvider.CreateDecryptor(rgbKey, rgbIV);
                CryptoStream cryptoStream = new CryptoStream(memoryStream, x, CryptoStreamMode.Read);
                memoryStream.Write(data, 0, data.Length);

                memoryStream.Position = 0;
                decrypted = new StreamReader(cryptoStream).ReadToEnd();
                cryptoStream.Close();
                memoryStream.Dispose();
                return decrypted;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public Task SendAsync(IdentityMessage message)
        {
            // Emails will be sent from this address
            var from = "nak290284@gmail.com";
            var pass = "Vkb5TitOUJ7sewwJD2v3odZeWxnpPT/2";

            // Setting up SMTP client
            SmtpClient client = new SmtpClient("smtp.gmail.com", 587);
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.UseDefaultCredentials = false;
            client.Credentials = new System.Net.NetworkCredential(from, Decrypt(pass));
            client.EnableSsl = true;

            // Create email
            var mail = new MailMessage(from, message.Destination);
            mail.Subject = message.Subject;
            mail.Body = message.Body;
            mail.IsBodyHtml = true;

            // Send email
            return client.SendMailAsync(mail);

            // Plug in your email service here to send an email.
            //return Task.FromResult(0);
        }
    }

    public class SmsService : IIdentityMessageService
    {
        public Task SendAsync(IdentityMessage message)
        {
            // Plug in your SMS service here to send a text message.
            return Task.FromResult(0);
        }
    }

    // Configure the application user manager used in this application. UserManager is defined in ASP.NET Identity and is used by the application.
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        public ApplicationUserManager(IUserStore<ApplicationUser> store)
            : base(store)
        {
        }

        public static ApplicationUserManager Create(IdentityFactoryOptions<ApplicationUserManager> options, IOwinContext context) 
        {
            var manager = new ApplicationUserManager(new UserStore<ApplicationUser>(context.Get<ApplicationDbContext>()));
            // Configure validation logic for usernames
            manager.UserValidator = new UserValidator<ApplicationUser>(manager)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            manager.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = true,
                RequireDigit = true,
                RequireLowercase = true,
                RequireUppercase = true,
            };

            // Configure user lockout defaults
            manager.UserLockoutEnabledByDefault = true;
            manager.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            manager.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            manager.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            manager.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            manager.EmailService = new EmailService();
            manager.SmsService = new SmsService();
            var dataProtectionProvider = options.DataProtectionProvider;
            if (dataProtectionProvider != null)
            {
                manager.UserTokenProvider = 
                    new DataProtectorTokenProvider<ApplicationUser>(dataProtectionProvider.Create("ASP.NET Identity"));
            }
            return manager;
        }
    }

    // Configure the application sign-in manager which is used in this application.
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        public ApplicationSignInManager(ApplicationUserManager userManager, IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        public static ApplicationSignInManager Create(IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            return new ApplicationSignInManager(context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}
