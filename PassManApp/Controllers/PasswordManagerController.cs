using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PassManApp.Data;
using PassManApp.Models;
using System.Security.Claims;


namespace PassManApp.Controllers
{
    [Authorize]

    public class PasswordManagerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IDataProtector _protector;

        public PasswordManagerController(ApplicationDbContext context, IDataProtectionProvider provider)
        {
            _context = context;
            _protector = provider.CreateProtector("PasswordManager_Protector");
        }

        public async Task<IActionResult> Index()
        {
            var userId = User.Identity.Name;  // Get the current logged-in user ID
            var passwords = _context.PasswordEntries.Where(p => p.UserId == userId).ToList();
            foreach (var password in passwords)
            {
                password.Password = _protector.Unprotect(password.Password);
            }
            return View(passwords);
        }

        public IActionResult Create() => View();

        [HttpPost]
        public async Task<IActionResult> Create(PasswordEntry model)
        {
            if (ModelState.IsValid)
            {

                model.UserId = User.Identity.Name;
                model.Password = _protector.Protect(model.Password);
                model.CreatedAt = DateTime.Now;
                _context.PasswordEntries.Add(model);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ChangePassword(int id)
        {
            // Find the password entry by ID
            var passwordEntry = await _context.PasswordEntries.FindAsync(id);

            if (passwordEntry == null || passwordEntry.UserId != User.Identity.Name)
            {
                return NotFound();  // Ensure the entry exists and belongs to the current user
            }

            // Populate the view model with the password entry details
            var model = new ChangePasswordViewModel
            {
                Id = passwordEntry.Id,
               

            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (model.NewPassword != model.ConfirmPassword)
            {
                ViewBag.ErrorMessage = "New password and confirmation do not match.";
                return View(model);
            }

            // Find the password entry
            var passwordEntry = await _context.PasswordEntries.FindAsync(model.Id);
            if (passwordEntry == null || passwordEntry.UserId != User.Identity.Name)
            {
                return NotFound();  // Ensure the entry exists and belongs to the current user
            }

            // Encrypt the new password before storing it
            var encryptedPassword = _protector.Protect(model.NewPassword);

            // Update the password entry with the new password
            passwordEntry.Password = encryptedPassword;
            _context.PasswordEntries.Update(passwordEntry);
            await _context.SaveChangesAsync();

            ViewBag.SuccessMessage = "Password changed successfully!";
            return RedirectToAction(nameof(Index));
 
        }

        // Delete password entry
        [HttpPost]
      
        public async Task<IActionResult> Delete(int id)
        {
            var passwordEntry = await _context.PasswordEntries.FindAsync(id);
            if (passwordEntry == null || passwordEntry.UserId != User.Identity.Name)
            {
                return NotFound();
            }

            _context.PasswordEntries.Remove(passwordEntry);
            await _context.SaveChangesAsync();

            return RedirectToAction("Index");
        }
    }

}
