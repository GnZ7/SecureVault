using System.ComponentModel.DataAnnotations;

namespace SecureVault.Client.Models
{
    public class RegisterModel {
        [Required] public string? UserName { get; set; }
        [Required][DataType(DataType.Password)] public string? Password { get; set; }
        public string? Role { get; set; }
    }
}
