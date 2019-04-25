using JWT;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Web.Http;

namespace JWTPlay2.Controller
{

    [RoutePrefix("api/auth")]
    public class AccountController : ApiController
    {
        PizzaSalesEntities db = new PizzaSalesEntities();
        [AllowAnonymous]       
        [HttpPost]
        [Route("login")]
        public HttpResponseMessage Login([FromBody]User user)
        {
            HttpResponseMessage response = null;
            if (ModelState.IsValid)
            {
                
                var existingUser = db.Users.FirstOrDefault(u => u.username == user.username);

                if (existingUser == null)
                {
                    response = Request.CreateResponse(HttpStatusCode.NotFound);
                }
                else
                {
                    if (existingUser.password == user.password)
                    {
                        object dbUser;
                        var token = CreateToken(existingUser, out dbUser);
                        response = Request.CreateResponse(new { dbUser, token });
                    }
                    else
                    {                       
                        response = Request.CreateErrorResponse(HttpStatusCode.BadRequest, ModelState);
                    }
                }
            }
            else
            {
                response = Request.CreateErrorResponse(HttpStatusCode.BadRequest, ModelState);
            }
            return response;
        }

        [Authorize]
        [HttpPost]
        [Route("me")]
        public IHttpActionResult Me()
        {
            ClaimsIdentity claimsIdentity = User.Identity as ClaimsIdentity;

            var claims = claimsIdentity.Claims.Select(x => new { type = x.Type, value = x.Value }).ToList();

            return Ok(new {
                firstName = claims.ElementAt(0).value,
                lastName = claims.ElementAt(1).value,
                email = claims.ElementAt(2).value,
                userId = claims.ElementAt(3).value,
            });
        }

        private static string CreateToken(User user, out object dbUser)
        {
            var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var expiry = Math.Round((DateTime.UtcNow.AddHours(2) - unixEpoch).TotalSeconds);
            var issuedAt = Math.Round((DateTime.UtcNow - unixEpoch).TotalSeconds);
            var notBefore = Math.Round((DateTime.UtcNow.AddMonths(6) - unixEpoch).TotalSeconds);


            var payload = new Dictionary<string, object>
            {
                {"firstName", user.firstName},
                {"lastName", user.lastName},
                {"email", user.email},
                {"userId", user.user_id},
                {"iat", issuedAt},
                {"exp", expiry}
            };

            //var secret = ConfigurationManager.AppSettings.Get("jwtKey");
            string apikey = ConfigurationManager.AppSettings.Get("secret").ToString();

            var token = JsonWebToken.Encode(payload, apikey, JwtHashAlgorithm.HS256);

            dbUser = new { user.email, user.user_id };
            return token;
        }

        public static string CreateSalt()
        {
            var data = new byte[0x10];
            using (var cryptoServiceProvider = new RNGCryptoServiceProvider())
            {
                cryptoServiceProvider.GetBytes(data);
                return Convert.ToBase64String(data);
            }
        }

        /// <summary>
        ///     Encrypts a password using the given salt
        /// </summary>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <returns></returns>
        public static string EncryptPassword(string password, string salt)
        {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = string.Format("{0}{1}", salt, password);
                var saltedPasswordAsBytes = Encoding.UTF8.GetBytes(saltedPassword);
                return Convert.ToBase64String(sha256.ComputeHash(saltedPasswordAsBytes));
            }
        }
    }
}
