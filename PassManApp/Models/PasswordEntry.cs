namespace PassManApp.Models
{
    public class PasswordEntry
    {
        public int Id { get; set; }
        public string Website { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
        public DateTime CreatedAt { get; set; }
    }

}
