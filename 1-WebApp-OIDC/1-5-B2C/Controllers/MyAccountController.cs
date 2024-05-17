using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Hosting;
using Microsoft.Identity.Abstractions;
using Microsoft.Identity.Web.UI;


namespace mywebapp.Controllers
{
    [AllowAnonymous]
    [Area("MicrosoftIdentity")]
    [Route("[area]/[controller]/[action]")]
    public class MyAccountController : Controller
    {

        [HttpGet("{scheme?}")]
        public IActionResult SignIn([FromRoute] string scheme)
        {
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
            var redirectUrl = Url.Content("~/");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items["policy"] = "B2C_1_test_signup_signin";

            return Challenge(properties, scheme);
        }

        [HttpGet("{scheme?}")]
        public async Task<IActionResult> SignOut([FromRoute] string scheme)
        {
            scheme ??= OpenIdConnectDefaults.AuthenticationScheme;
            var redirectUrl = Url.Content("~/");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            //obtain the id_token
            var idToken = await HttpContext.GetTokenAsync("id_token");
            //send the id_token value to the authentication middleware
            properties.Items["id_token_hint"] = idToken;

            return SignOut(properties, CookieAuthenticationDefaults.AuthenticationScheme, scheme);
        }
    }
}