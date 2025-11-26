<?php
include 'includes/header.php'; // Includes auth check and DB connection

// =================================================================
// SECURITY CHECK: ONLY SUPER ADMINS CAN ACCESS THIS PAGE
// =================================================================
if (!isset($_SESSION['admin_role']) || $_SESSION['admin_role'] !== 'superadmin') {
    // If not a superadmin, show an error and stop execution
    echo "<h1>Access Denied</h1><p>You do not have permission to access this page.</p>";
    include 'includes/footer.php';
    exit;
}

// --- HANDLE POST REQUESTS (ADD, UPDATE, DELETE) ---

// 1. HANDLE DELETE
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['delete_id'])) {
    $id_to_delete = $_POST['delete_id'];
    
    // CRITICAL: Prevent a user from deleting their own account
    if ($id_to_delete == $_SESSION['admin_id']) {
        $error_msg = "Error: You cannot delete your own account.";
    } else {
        $stmt = $pdo->prepare("DELETE FROM admins WHERE id = ?");
        $stmt->execute([$id_to_delete]);
        header("Location: manage_admins.php?status=deleted");
        exit;
    }
}

// 2. HANDLE ADD/UPDATE
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['username'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $role = $_POST['role'];
    
    // Check if it's an UPDATE or a new ADD
    if (isset($_POST['update_id']) && !empty($_POST['update_id'])) {
        // --- UPDATE an existing admin ---
        $id_to_update = $_POST['update_id'];
        
        if (!empty($password)) {
            // If a new password is provided, hash it and update it
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("UPDATE admins SET username = ?, password = ?, role = ? WHERE id = ?");
            $stmt->execute([$username, $hashedPassword, $role, $id_to_update]);
        } else {
            // If password field is empty, do NOT update the password
            $stmt = $pdo->prepare("UPDATE admins SET username = ?, role = ? WHERE id = ?");
            $stmt->execute([$username, $role, $id_to_update]);
        }
        header("Location: manage_admins.php?status=updated");
        exit;

    } else {
        // --- ADD a new admin ---
        if (empty($username) || empty($password)) {
            $error_msg = "Username and Password are required to add a new admin.";
        } else {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT id FROM admins WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $error_msg = "Error: This username already exists.";
            } else {
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("INSERT INTO admins (username, password, role) VALUES (?, ?, ?)");
                $stmt->execute([$username, $hashedPassword, $role]);
                header("Location: manage_admins.php?status=added");
                exit;
            }
        }
    }
}

// --- PREPARE FOR DISPLAY ---

// Check if we are in "edit mode"
$edit_mode = false;
$admin_to_edit = null;
if (isset($_GET['edit_id'])) {
    $edit_mode = true;
    $stmt = $pdo->prepare("SELECT * FROM admins WHERE id = ?");
    $stmt->execute([$_GET['edit_id']]);
    $admin_to_edit = $stmt->fetch(PDO::FETCH_ASSOC);
}

// Fetch all admins to display in the list
$all_admins = $pdo->query("SELECT id, username, role FROM admins ORDER BY id ASC")->fetchAll(PDO::FETCH_ASSOC);
?>

<style>
    .status-msg { padding: 15px; margin-bottom: 20px; border-radius: 5px; color: #fff; }
    .status-msg.success { background-color: #2ecc71; }
    .status-msg.error { background-color: #e74c3c; }
</style>

<h1>Manage Admins</h1>

<?php if (isset($error_msg)) echo '<div class="status-msg error">' . $error_msg . '</div>'; ?>
<?php if (isset($_GET['status'])) echo '<div class="status-msg success">Action completed successfully!</div>'; ?>


<!-- ADD/EDIT FORM CARD -->
<div class="card">
    <h3><?php echo $edit_mode ? 'Edit Admin' : 'Add New Admin'; ?></h3>
    <form action="manage_admins.php" method="POST">
        <?php if ($edit_mode): ?>
            <input type="hidden" name="update_id" value="<?php echo $admin_to_edit['id']; ?>">
        <?php endif; ?>
        
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" value="<?php echo $edit_mode ? htmlspecialchars($admin_to_edit['username']) : ''; ?>" required>
        
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" placeholder="<?php echo $edit_mode ? 'Leave blank to keep current password' : ''; ?>" <?php echo !$edit_mode ? 'required' : ''; ?>>

        <label for="role">Role:</label>
        <select name="role" id="role" required>
            <option value="admin" <?php echo ($edit_mode && $admin_to_edit['role'] == 'admin') ? 'selected' : ''; ?>>Admin</option>
            <option value="superadmin" <?php echo ($edit_mode && $admin_to_edit['role'] == 'superadmin') ? 'selected' : ''; ?>>Super Admin</option>
        </select>
        
        <button type="submit"><?php echo $edit_mode ? 'Update Admin' : 'Add Admin'; ?></button>
        <?php if ($edit_mode): ?>
            <a href="manage_admins.php" style="margin-left: 10px; text-decoration: none; color: #777;">Cancel Edit</a>
        <?php endif; ?>
    </form>
</div>


<!-- EXISTING ADMINS LIST CARD -->
<div class="card">
    <h3>Existing Admins</h3>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Role</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($all_admins as $admin): ?>
            <tr>
                <td><?php echo $admin['id']; ?></td>
                <td><?php echo htmlspecialchars($admin['username']); ?></td>
                <td><span class="role-badge role-<?php echo $admin['role']; ?>"><?php echo ucfirst($admin['role']); ?></span></td>
                <td class="actions">
                    <a href="manage_admins.php?edit_id=<?php echo $admin['id']; ?>" class="edit-btn">Edit</a>
                    <?php 
                    // Show delete button ONLY if it's not the currently logged-in user
                    if ($admin['id'] != $_SESSION['admin_id']): 
                    ?>
                        <form action="manage_admins.php" method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to delete this admin? This action cannot be undone.');">
                            <input type="hidden" name="delete_id" value="<?php echo $admin['id']; ?>">
                            <button type="submit" class="delete-btn">Delete</button>
                        </form>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<style>
    .role-badge { padding: 3px 8px; border-radius: 12px; color: white; font-size: 0.8em; font-weight: bold; }
    .role-superadmin { background-color: #e74c3c; }
    .role-admin { background-color: #3498db; }
</style>

<?php include 'includes/footer.php'; ?>