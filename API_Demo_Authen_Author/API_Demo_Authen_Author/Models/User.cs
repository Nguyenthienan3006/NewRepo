using System;
using System.Collections.Generic;

namespace API_Demo_Authen_Author.Models
{
    public partial class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string? FullName { get; set; }
        public string? Email { get; set; }
        public string? Role { get; set; }
    }
}
