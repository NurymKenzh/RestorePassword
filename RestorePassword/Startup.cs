using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(RestorePassword.Startup))]
namespace RestorePassword
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
