using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PassManApp.Data;
using PassManApp.Models;
using PassManApp.Services;

namespace PassManApp.Controllers
{
    [Authorize]
    
    public class PasswordManagerController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly PasswordService _passwordService;

        public PasswordManagerController(ApplicationDbContext context, PasswordService passwordService)
        {
            _context = context;
            _passwordService = passwordService;
        }

        public async Task<IActionResult> Index()
        {
            var passwords = await _context.PasswordEntries.ToListAsync();
            return View(passwords);
        }

        public IActionResult Create() => View();

        [HttpPost]
        public async Task<IActionResult> Create(PasswordEntry model)
        {
            if (ModelState.IsValid)
            {
                model.Password = _passwordService.EncryptPassword(model.Password);
                model.CreatedAt = DateTime.Now;
                _context.PasswordEntries.Add(model);
                await _context.SaveChangesAsync();
                return RedirectToAction(nameof(Index));
            }
            return View(model);
        }

        public async Task<IActionResult> Details(int id)
        {
            var passwordEntry = await _context.PasswordEntries.FindAsync(id);
            passwordEntry.Password = _passwordService.DecryptPassword(passwordEntry.Password);
            return View(passwordEntry);
        }
    }

}
