/////////////////////////////////////////////////////
// This is a custom attribute.                     //
// Check if user prop has role inserted from enum. //
// Usage in controllers mainly                     //
/////////////////////////////////////////////////////

using System;
using System.Linq;
using System.Security.Claims;


    // 1. Attribute implemention
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
    public class AuthorizeRolesAttribute : AuthorizeAttribute, IAuthorizationFilter
    {
    // 2. Enum with roles
    public enum Roles : int
    {
        Unset = 0,
        User = 1,
        Support = 2,
        Marketing = 3,
        Programmer = 4,
        SysAdmin = 5,
        FullAdmin = 6
    }

        public Roles[] roles { get; set; }
        public AuthorizeRolesAttribute(params Roles[] roles)
        {
            this.roles = roles;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var user = context.HttpContext.User;

            if (!user.Identity.IsAuthenticated)
            {
                return;
            }

            var someService = context.HttpContext.RequestServices.GetService<IUserService>();

            if (!CheckRoles(someService, user))
            {
                context.Result = new StatusCodeResult((int)System.Net.HttpStatusCode.Forbidden);
                return;
            }
        }
            public bool CheckRoles(IUserDbService service, ClaimsPrincipal user)
            {
                var isUser = service.CheckUserRole(user.Identity.Name);
                var isChecked = roles.ToList().Contains(isUser.Roles);

                return isChecked;
            }
     }

// 3. Add Service layer
public User CheckUserRole(string userName)
{
    var Result1 = GetAllAsNoTracking()
        .Where(e => e.UserName == userName)
        .FirstOrDefault();

    return Result1;
}
public IQueryable<User> GetAllAsNoTracking()
{
    return userManager.Users.AsQueryable().AsNoTracking();
}

// 4. Usage in controllers
/*
        [AuthorizeRoles(Roles.SysAdmin, Roles.FullAdmin)] 
        public async Task<ActionResult<List<Softwares>>> GetSofts()

        {
          var result = await _userService.GetSoftwares().ToListAsync();
            if (result != null)
            {
                return Ok(result);
            }

            return NotFound();
        }
*/
