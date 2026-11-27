<?php
if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params(0);
    session_start();
}

// Strict Super Admin Session Check
$active_user = $_SESSION['super_admin'] ?? null;
$is_super_admin = true; // Always true in this file

// Heartbeat timeout (30 minutes)
$timeout_duration = 1800;
if (isset($_SESSION['last_ping']) && (time() - $_SESSION['last_ping'] > $timeout_duration)) {
    session_unset(); session_destroy();
    header("Location: superadmin-login.php");
    exit();
}
$_SESSION['last_ping'] = time();

// Auth Guard
if (!$active_user) {
    header("Location: superadmin-login.php");
    exit();
}

$dbConfigPath = file_exists(__DIR__ . '/common/db_connection.php')
    ? __DIR__ . '/common/db_connection.php'
    : (file_exists(__DIR__ . '/../backend/config/db_connection.php') ? __DIR__ . '/../backend/config/db_connection.php' : null);
if ($dbConfigPath) {
    require_once $dbConfigPath;
}

try {
    $pdo = Database::connect();

    // Auto-heal id_verifications schema if verification_id lacks AUTO_INCREMENT / Primary Key
    try {
        $chk = $pdo->query("SHOW COLUMNS FROM `id_verifications` WHERE `Field` = 'verification_id'")->fetch(PDO::FETCH_ASSOC);
        if ($chk && empty($chk['Key'])) {
            $pdo->exec("UPDATE `id_verifications` SET `verification_id` = 1 WHERE `verification_id` = 0");
            $pdo->exec("ALTER TABLE `id_verifications` MODIFY COLUMN `verification_id` BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT, ADD PRIMARY KEY (`verification_id`)");
        }
    } catch (\Throwable $migErr) {}

    // Re-fetch fresh data from database to ensure account status is current
    $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE admin_id = ? LIMIT 1");
    $stmt->execute([$active_user['id']]);
    $fresh_user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$fresh_user || $fresh_user['status'] !== 'approved' || $fresh_user['role'] !== 'super_admin') {
        session_unset(); session_destroy();
        header("Location: superadmin-login.php?error=access_revoked");
        exit();
    }

    // Map variables for backward compatibility across the file
    $_SESSION['admin_id']       = $active_user['id'];
    $_SESSION['admin_username'] = $active_user['username'];
    $_SESSION['admin_role']     = $active_user['role'];
    $_SESSION['admin_name']     = $active_user['name'];
    $_SESSION['permissions']    = $active_user['permissions'];

    $admin_id       = $active_user['id'];
    $admin_username = $active_user['username'];
    $admin_role     = $active_user['role'];
    $admin_name     = $active_user['name'];
    $permissions    = $active_user['permissions'];

    // Handle Logo Upload Action
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'upload_logo') {
        if (isset($_FILES['logo_file']) && $_FILES['logo_file']['error'] === UPLOAD_ERR_OK) {
            $fileTmpPath = $_FILES['logo_file']['tmp_name'];
            $fileName = $_FILES['logo_file']['name'];
            $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));

            if ($fileExtension === 'png') {
                $destPath = __DIR__ . '/img/logo.png';
                $destDir = dirname($destPath);
                if (!file_exists($destDir)) {
                    mkdir($destDir, 0777, true);
                }

                if (move_uploaded_file($fileTmpPath, $destPath)) {
                    $_SESSION['logo_upload_status'] = 'success';
                } else {
                    $_SESSION['logo_upload_status'] = 'error';
                    $_SESSION['logo_upload_msg'] = "Failed to save the file to active directory.";
                }
            } else {
                $_SESSION['logo_upload_status'] = 'error';
                $_SESSION['logo_upload_msg'] = "Invalid file format. Please upload a PNG image.";
            }
        } else {
            $_SESSION['logo_upload_status'] = 'error';
            $_SESSION['logo_upload_msg'] = "Upload error: " . ($_FILES['logo_file']['error'] ?? 'No file uploaded.');
        }

        header("Location: superadmin-dashboard.php?tab=logo");
        exit();
    }

    // ── AJAX HANDLER FOR PROVIDER SERVICES FULL CONTAINER VIEW (GET & POST) ───
    if (isset($_REQUEST['ajax_action']) && $_REQUEST['ajax_action'] === 'fetch_provider_services_view') {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['toggle_service_id'], $_POST['new_service_status'])) {
                $st = $_POST['new_service_status'];
                if (in_array($st, ['approved', 'pending', 'rejected'])) {
                    $srv_id = (int) $_POST['toggle_service_id'];
                    $active_val = ($st === 'approved') ? 1 : 0;
                    $pdo->prepare("UPDATE `serveasy-services` SET approval_status=?, is_active=? WHERE id=?")->execute([$st, $active_val, $srv_id]);

                    if ($st === 'approved') {
                        $p_id_stmt = $pdo->prepare("SELECT provider_id FROM `serveasy-services` WHERE id=?");
                        $p_id_stmt->execute([$srv_id]);
                        $prov_id = $p_id_stmt->fetchColumn();
                        if ($prov_id) {
                            $pdo->prepare("UPDATE `serveasy-providers` SET verified_status='approved', is_active=1 WHERE id=?")->execute([$prov_id]);
                        }
                    }
                    header('Content-Type: application/json');
                    echo json_encode(['ok' => true, 'message' => "Service " . ($st === 'approved' ? 'approved' : 'rejected') . " successfully."]);
                    exit();
                }
            }
            header('Content-Type: application/json');
            echo json_encode(['ok' => false, 'message' => 'Invalid status parameter.']);
            exit();
        }

        $provider_id = (int)($_REQUEST['provider_id'] ?? 0);
        $from = $_REQUEST['from'] ?? 'dealer';
        if (!$provider_id) {
            echo '<div class="alert alert-danger m-4">Invalid provider ID specified.</div>';
            exit();
        }

        // Fetch provider info
        $p_stmt = $pdo->prepare("SELECT sp.id, COALESCE(pp.full_name, 'Service Provider') AS full_name, sp.email as email_address, sp.phone as phone_number, sp.is_active, sp.verified_status, sp.created_at, COALESCE(c.company_name, '') as company_name 
                                 FROM `serveasy-providers` sp 
                                 LEFT JOIN `provider_profiles` pp ON pp.provider_id = sp.id 
                                 LEFT JOIN `serveasy-company` c ON c.provider_id = sp.id 
                                 WHERE sp.id = ? LIMIT 1");
        $p_stmt->execute([$provider_id]);
        $provider = $p_stmt->fetch(PDO::FETCH_ASSOC);

        if (!$provider) {
            echo '<div class="alert alert-warning m-4"><i class="fas fa-exclamation-triangle mr-2"></i>Service Provider not found.</div>';
            exit();
        }

        $displayName = !empty($provider['company_name']) ? $provider['company_name'] : $provider['full_name'];
        $subName = !empty($provider['company_name']) && !empty($provider['full_name']) ? $provider['full_name'] : '';

        // Services query
        $s_stmt = $pdo->prepare("SELECT s.*, sub.name as subcategory_name 
                                 FROM `serveasy-services` s 
                                 LEFT JOIN `serveasy-subcategories` sub ON s.subcategory_id = sub.id 
                                 WHERE s.provider_id = ? 
                                 ORDER BY s.id DESC");
        $s_stmt->execute([$provider_id]);
        $services = $s_stmt->fetchAll(PDO::FETCH_ASSOC);
        $total_services = count($services);
        $approved_count = count(array_filter($services, function($s) { return ($s['approval_status'] ?? '') === 'approved'; }));
        $pending_count = count(array_filter($services, function($s) { return ($s['approval_status'] ?? 'pending') === 'pending'; }));
        $rejected_count = count(array_filter($services, function($s) { return ($s['approval_status'] ?? '') === 'rejected'; }));
        ?>

        <!-- Navigation Buttons -->
        <div class="mb-4">
            <div class="d-flex align-items-center justify-content-between flex-wrap" style="gap: 10px;">
                <div class="d-flex align-items-center" style="gap: 10px;">
                    <button type="button" class="btn btn-outline-secondary btn-sm font-weight-bold" 
                        style="border-radius: 8px; padding: 7px 16px; background: #fff; border-color: #d1d3e2;"
                        onclick="loadDetail('dealer', <?= $provider_id ?>)">
                        <i class="fas fa-arrow-left mr-1"></i> Back to Provider Details
                    </button>
                    <button type="button" class="btn btn-light btn-sm font-weight-bold text-muted" 
                        style="border-radius: 8px; padding: 7px 14px;"
                        onclick="loadSection('dealer')">
                        <i class="fas fa-handshake mr-1"></i> All Providers
                    </button>
                </div>
                <div>
                    <span class="badge badge-emerald px-3 py-2 rounded-pill font-weight-bold" style="background: #05c279; color: #fff; font-size: 0.85rem;">
                        <i class="fas fa-id-badge mr-1"></i> Provider ID #<?= $provider_id ?>
                    </span>
                </div>
            </div>
        </div>

        <!-- Heading -->
        <div class="d-sm-flex align-items-center justify-content-between mb-4">
            <div>
                <h1 class="h3 mb-1 text-gray-800 font-weight-bold">
                    <i class="fas fa-wrench mr-2" style="color: #05c279;"></i>
                    <?= htmlspecialchars($displayName) ?> – Listed Services
                </h1>
                <p class="text-muted small mb-0">Browse and manage all catalog services registered by this provider or company.</p>
            </div>
        </div>

        <!-- Provider Overview Card -->
        <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px; background: #fff;">
            <div class="card-body p-4">
                <div class="row align-items-center">
                    <div class="col-lg-6 col-md-12 mb-3 mb-lg-0">
                        <div class="d-flex align-items-center">
                            <div class="rounded-circle d-flex align-items-center justify-content-center text-white mr-3 font-weight-bold shadow-sm"
                                style="width: 56px; height: 56px; min-width: 56px; background: linear-gradient(135deg, #05c279, #038a56); font-size: 1.4rem;">
                                <?= strtoupper(substr($displayName, 0, 1)) ?>
                            </div>
                            <div>
                                <h5 class="font-weight-bold text-gray-800 mb-1">
                                    <?= htmlspecialchars($displayName) ?>
                                    <?php if ($subName): ?>
                                        <span class="text-muted small font-weight-normal">(<?= htmlspecialchars($subName) ?>)</span>
                                    <?php endif; ?>
                                </h5>
                                <div class="text-muted small">
                                    <?php if (!empty($provider['phone_number'])): ?>
                                        <span class="mr-3"><i class="fas fa-phone mr-1" style="color: #05c279;"></i> <?= htmlspecialchars($provider['phone_number']) ?></span>
                                    <?php endif; ?>
                                    <?php if (!empty($provider['email_address'])): ?>
                                        <span class="mr-3"><i class="fas fa-envelope mr-1" style="color: #05c279;"></i> <?= htmlspecialchars($provider['email_address']) ?></span>
                                    <?php endif; ?>
                                    <span><i class="fas fa-calendar-alt mr-1" style="color: #05c279;"></i> Joined <?= htmlspecialchars($provider['created_at'] ?? 'N/A') ?></span>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-lg-6 col-md-12">
                        <div class="d-flex justify-content-lg-end justify-content-start flex-wrap" style="gap: 10px;">
                            <div class="px-3 py-2 rounded text-center" style="background: rgba(5,194,121,0.08); min-width: 90px; border: 1px solid rgba(5,194,121,0.15);">
                                <div class="font-weight-bold" style="font-size: 1.3rem; color: #05c279;"><?= $total_services ?></div>
                                <div class="text-muted small font-weight-bold" style="font-size: 0.72rem; text-transform: uppercase;">Total</div>
                            </div>
                            <div class="px-3 py-2 rounded text-center" style="background: rgba(28,200,138,0.08); min-width: 90px; border: 1px solid rgba(28,200,138,0.2);">
                                <div class="font-weight-bold text-success" style="font-size: 1.3rem;"><?= $approved_count ?></div>
                                <div class="text-muted small font-weight-bold" style="font-size: 0.72rem; text-transform: uppercase;">Approved</div>
                            </div>
                            <div class="px-3 py-2 rounded text-center" style="background: rgba(246,194,62,0.1); min-width: 90px; border: 1px solid rgba(246,194,62,0.25);">
                                <div class="font-weight-bold text-warning" style="font-size: 1.3rem;"><?= $pending_count ?></div>
                                <div class="text-muted small font-weight-bold" style="font-size: 0.72rem; text-transform: uppercase;">Pending</div>
                            </div>
                            <div class="px-3 py-2 rounded text-center" style="background: rgba(231,74,59,0.08); min-width: 90px; border: 1px solid rgba(231,74,59,0.2);">
                                <div class="font-weight-bold text-danger" style="font-size: 1.3rem;"><?= $rejected_count ?></div>
                                <div class="text-muted small font-weight-bold" style="font-size: 0.72rem; text-transform: uppercase;">Rejected</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Services Table Card -->
        <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px; overflow: hidden;">
            <div class="card-header bg-white py-3 d-flex align-items-center justify-content-between" style="border-bottom: 2px solid #f0f0f0;">
                <h6 class="m-0 font-weight-bold text-gray-800" style="font-size: 1rem;">
                    <i class="fas fa-list-ul mr-2" style="color: #05c279;"></i> Services Catalog (<?= $total_services ?>)
                </h6>
                <?php if ($total_services > 0): ?>
                    <span class="text-muted small">Click any row to open the complete service details</span>
                <?php endif; ?>
            </div>
            <div class="card-body p-0">
                <?php if (empty($services)): ?>
                    <div class="text-center py-5">
                        <div class="mb-3 text-muted" style="opacity: 0.35;">
                            <i class="fas fa-tools fa-4x" style="color: #05c279;"></i>
                        </div>
                        <h5 class="font-weight-bold text-gray-800">No Services Listed Yet</h5>
                        <p class="text-muted small mb-0">This service provider or company has not registered any services on the platform.</p>
                        <button type="button" class="btn btn-outline-secondary btn-sm font-weight-bold mt-4" onclick="loadDetail('dealer', <?= $provider_id ?>)">
                            <i class="fas fa-arrow-left mr-1"></i> Return to Provider Details
                        </button>
                    </div>
                <?php else: ?>
                    <div class="table-responsive">
                        <table class="table green-table mb-0">
                            <thead>
                                <tr>
                                    <th style="width: 70px;">ID</th>
                                    <th>Service Name & Description</th>
                                    <th>Subcategory</th>
                                    <th>Base Price</th>
                                    <th>Duration</th>
                                    <th>Status</th>
                                    <th style="text-align: right !important; padding-right: 1.5rem;">Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($services as $srv): 
                                    $srv_id = (int)$srv['id'];
                                    $srv_status = $srv['approval_status'] ?? 'pending';
                                    $status_class = $srv_status === 'approved' ? 'badge-success' : ($srv_status === 'rejected' ? 'badge-danger' : 'badge-warning');
                                ?>
                                    <tr onclick="loadDetail('service', <?= $srv_id ?>)" style="cursor: pointer;">
                                        <td class="font-weight-bold text-muted">#<?= $srv_id ?></td>
                                        <td>
                                            <div class="font-weight-bold text-gray-800" style="font-size: 0.95rem;"><?= htmlspecialchars($srv['name']) ?></div>
                                            <?php if (!empty($srv['description'])): ?>
                                                <div class="text-muted small" style="max-width: 380px;"><?= htmlspecialchars(substr($srv['description'], 0, 90)) . (strlen($srv['description']) > 90 ? '...' : '') ?></div>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <span class="badge badge-light text-dark px-2 py-1 font-weight-normal border">
                                                <?= htmlspecialchars($srv['subcategory_name'] ?? 'General') ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="font-weight-bold" style="font-size: 1rem; color: #05c279;">
                                                ₹<?= number_format((float)$srv['base_price'], 2) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="text-muted small">
                                                <i class="far fa-clock mr-1" style="color: #05c279;"></i><?= (int)$srv['duration_minutes'] ?> mins
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge <?= $status_class ?> px-2 py-1" style="font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.5px;">
                                                <?= ucfirst($srv_status) ?>
                                            </span>
                                        </td>
                                        <td style="text-align: right !important; padding-right: 1.5rem;" onclick="event.stopPropagation()">
                                            <div class="d-inline-flex" style="gap: 6px;">
                                                <?php if ($srv_status !== 'approved'): ?>
                                                    <button type="button" class="btn btn-outline-success btn-sm font-weight-bold py-1 px-2"
                                                        style="border-width:2px; border-radius:6px; font-size: 0.78rem;"
                                                        title="Approve Service"
                                                        onclick="submitProviderServiceAction(<?= $srv_id ?>, 'approved', <?= $provider_id ?>)">
                                                        <i class="fas fa-check mr-1"></i> Accept
                                                    </button>
                                                <?php endif; ?>
                                                <?php if ($srv_status !== 'rejected'): ?>
                                                    <button type="button" class="btn btn-outline-danger btn-sm font-weight-bold py-1 px-2"
                                                        style="border-width:2px; border-radius:6px; font-size: 0.78rem;"
                                                        title="Reject Service"
                                                        onclick="submitProviderServiceAction(<?= $srv_id ?>, 'rejected', <?= $provider_id ?>)">
                                                        <i class="fas fa-times mr-1"></i> Reject
                                                    </button>
                                                <?php endif; ?>
                                                <button type="button" class="btn btn-outline-secondary btn-sm font-weight-bold py-1 px-2"
                                                    style="border-width:2px; border-radius:6px; font-size: 0.78rem;"
                                                    title="View Full Service Details"
                                                    onclick="loadDetail('service', <?= $srv_id ?>)">
                                                    <i class="fas fa-external-link-alt mr-1"></i> View
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
        exit();
    }

    // ── AJAX HANDLER FOR LISTS (GET & POST) ─────────────────────────
    if (isset($_REQUEST['ajax_action']) && $_REQUEST['ajax_action'] === 'fetch_list') {
        $type = $_REQUEST['type'] ?? 'admin';
        if (!in_array($type, ['admin', 'dealer', 'user', 'verification', 'logo', 'service', 'blogs', 'categories', 'dealer_services', 'convenience_fee', 'payment_gateway', 'otp_config', 'smtp_settings', 'domain_config', 'profile', 'settings']))
            $type = 'admin';
        if ($type === 'profile') {
            include __DIR__ . '/components/profile-view.php';
            exit();
        }
        if ($type === 'settings') {
            if (!$is_super_admin) {
                echo '<div class="alert alert-danger font-weight-bold"><i class="fas fa-lock mr-2"></i>Access denied: System Settings are strictly restricted to Super Administrators.</div>';
                exit();
            }
            include __DIR__ . '/components/settings-view.php';
            exit();
        }
        if ($type === 'domain_config') {
            if (!$is_super_admin) {
                echo '<div class="alert alert-danger font-weight-bold"><i class="fas fa-lock mr-2"></i>Access denied: Live Domain Configuration is strictly restricted to Super Administrators.</div>';
                exit();
            }
            include __DIR__ . '/components/domain-config-view.php';
            exit();
        }
        if ($type === 'otp_config') {
            if (!$is_super_admin) {
                echo '<div class="alert alert-danger font-weight-bold"><i class="fas fa-lock mr-2"></i>Access denied: Global OTP Login Configuration is strictly restricted to Super Administrators.</div>';
                exit();
            }
            include __DIR__ . '/components/otp-config-view.php';
            exit();
        }
        if ($type === 'smtp_settings') {
            if (!$is_super_admin) {
                echo '<div class="alert alert-danger font-weight-bold"><i class="fas fa-lock mr-2"></i>Access denied: SMTP Configuration is strictly restricted to Super Administrators.</div>';
                exit();
            }
            include __DIR__ . '/components/smtp-settings-view.php';
            exit();
        }
        if ($type === 'payment_gateway') {
            if (!$is_super_admin) {
                echo '<div class="alert alert-danger font-weight-bold"><i class="fas fa-lock mr-2"></i>Access denied: Payment Gateway Key configuration is strictly restricted to Super Administrators.</div>';
                exit();
            }
            include __DIR__ . '/components/payment-gateway-view.php';
            exit();
        }
        if ($type === 'blogs') {
            $viewPath = file_exists(__DIR__ . '/components/blog-management-view.php')
                ? __DIR__ . '/components/blog-management-view.php'
                : __DIR__ . '/../frontend-admin/components/blog-management-view.php';
            include $viewPath;
            exit();
        }
        if ($type === 'categories') {
            $viewPath = file_exists(__DIR__ . '/components/category-management-view.php')
                ? __DIR__ . '/components/category-management-view.php'
                : __DIR__ . '/../frontend-admin/components/category-management-view.php';
            include $viewPath;
            exit();
        }
        if ($type === 'convenience_fee') {
            $viewPath = file_exists(__DIR__ . '/components/convenience-fee-view.php')
                ? __DIR__ . '/components/convenience-fee-view.php'
                : __DIR__ . '/../frontend-admin/components/convenience-fee-view.php';
            include $viewPath;
            exit();
        }
        if ($type === 'logo' && !$is_super_admin) {
            echo 'Access denied.';
            exit();
        }
        if (!$is_super_admin && empty($_SESSION['permissions'][$type]) && !in_array($type, ['admin', 'verification', 'service'])) {
            echo 'Access denied.';
            exit();
        }
        if (!$is_super_admin && in_array($type, ['verification', 'service']) && empty($_SESSION['permissions']['dealer'])) {
            echo 'Access denied.';
            exit();
        }
        if (!$is_super_admin && $type === 'admin') {
            echo 'Access denied.';
            exit();
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if (isset($_POST['toggle_service_id'], $_POST['new_service_status'])) {
                $id = (int) $_POST['toggle_service_id'];
                $st = $_POST['new_service_status'];
                if (in_array($st, ['approved', 'pending', 'rejected'])) {
                    $active_val = ($st === 'approved') ? 1 : 0;
                    $pdo->prepare("UPDATE `serveasy-services` SET approval_status=?, is_active=? WHERE id=?")->execute([$st, $active_val, $id]);

                    if ($st === 'approved') {
                        $p_id_stmt = $pdo->prepare("SELECT provider_id FROM `serveasy-services` WHERE id=?");
                        $p_id_stmt->execute([$id]);
                        $prov_id = $p_id_stmt->fetchColumn();
                        if ($prov_id) {
                            $pdo->prepare("UPDATE `serveasy-providers` SET verified_status='approved', is_active=1 WHERE id=?")->execute([$prov_id]);
                        }
                    }
                }
            }
            if (isset($_POST['toggle_member_id'], $_POST['new_member_status'])) {
                $id = (int) $_POST['toggle_member_id'];
                $st = $_POST['new_member_status'];
                if (in_array($st, ['approved', 'pending'])) {
                    $sid = $_SESSION['admin_id'] ?? null;
                    // Strict role check in query to prevent cross-role status hijacking
                    $pdo->prepare("UPDATE admin_users SET status=?, approved_by=?, approved_at=NOW() WHERE admin_id=? AND role=?")->execute([$st, $sid, $id, $type]);
                }
            }
            if (isset($_POST['permission_admin_id'], $_POST['perm_type'], $_POST['perm_val']) && $is_super_admin) {
                $pid = (int) $_POST['permission_admin_id'];
                $pt = $_POST['perm_type'];
                $pval = $_POST['perm_val'] ? 1 : 0;
                $ok = ['admin', 'dealer', 'user'];
                if (in_array($pt, $ok))
                    $pdo->prepare("UPDATE admin_users SET can_access_{$pt}=? WHERE admin_id=? AND role!='super_admin'")->execute([$pval, $pid]);
            }
            if (isset($_POST['toggle_user_id'], $_POST['new_user_status'])) {
                $id = (int) $_POST['toggle_user_id'];
                $st = $_POST['new_user_status'];
                if (in_array($st, ['active', 'inactive'])) {
                    $val = $st === 'active' ? 1 : 0;
                    $pdo->prepare("UPDATE site_user SET is_active=? WHERE id=?")->execute([$val, $id]);
                }
            }
            if (isset($_POST['toggle_dealer_verification_id'], $_POST['new_verification_status'])) {
                $dealer_id = (int) $_POST['toggle_dealer_verification_id'];
                $new_status = $_POST['new_verification_status']; // 'approved' or 'rejected'
                $rej_reason = trim($_POST['rejection_reason'] ?? '');
                $admin_id = $_SESSION['admin_id'] ?? null;

                if ($dealer_id && in_array($new_status, ['approved', 'rejected'])) {
                    $active_val = ($new_status === 'approved') ? 1 : 0;
                    $pdo->prepare("UPDATE `serveasy-providers` SET verified_status = ?, is_active = ? WHERE id = ?")->execute([$new_status, $active_val, $dealer_id]);

                    $v_check = $pdo->prepare("SELECT verification_id FROM id_verifications WHERE user_id = ? ORDER BY verification_id DESC LIMIT 1");
                    $v_check->execute([$dealer_id]);
                    $v_id = $v_check->fetchColumn();
                    if ($v_id) {
                        $pdo->prepare("UPDATE id_verifications SET verification_status = ?, rejection_reason = ?, verified_by = ?, verified_at = NOW() WHERE verification_id = ?")->execute([$new_status, ($new_status === 'rejected' && $rej_reason) ? $rej_reason : null, $admin_id, $v_id]);
                    }
                    header('Content-Type: application/json');
                    echo json_encode(['ok' => true, 'message' => "Service provider successfully " . ($new_status === 'approved' ? 'approved' : 'rejected') . "!"]);
                    exit();
                }
            }
            if (isset($_POST['toggle_dealer_id'], $_POST['new_dealer_status'])) {
                $id = (int) $_POST['toggle_dealer_id'];
                $st = $_POST['new_dealer_status'];
                if (in_array($st, ['active', 'inactive'])) {
                    $val = $st === 'active' ? 1 : 0;
                    $pdo->prepare("UPDATE `serveasy-providers` SET is_active=? WHERE id=?")->execute([$val, $id]);
                }
            }
            header('Content-Type: application/json');
            echo json_encode(['ok' => true]);
            exit();
        }

        if ($type === 'admin')
            $rows = $pdo->query("SELECT * FROM admin_users WHERE role='admin' ORDER BY admin_id DESC")->fetchAll(PDO::FETCH_ASSOC);
        elseif ($type === 'dealer')
            // Service providers live in serveasy-providers
            $rows = $pdo->query("SELECT sp.id, COALESCE(pp.full_name, 'Service Provider') AS full_name, sp.email as email_address, sp.phone as phone_number, COALESCE(sp.location_address, (SELECT address FROM `service_providers_address` WHERE provider_id = sp.id ORDER BY is_default DESC, id DESC LIMIT 1), '') as location_address, COALESCE(c.company_name, '') as company_name, sp.is_active, sp.verified_status, sp.created_at, (SELECT verification_id FROM id_verifications WHERE user_id = sp.id ORDER BY verification_id DESC LIMIT 1) as latest_verification_id, (SELECT verification_status FROM id_verifications WHERE user_id = sp.id ORDER BY verification_id DESC LIMIT 1) as latest_verification_status FROM `serveasy-providers` sp LEFT JOIN `provider_profiles` pp ON pp.provider_id = sp.id LEFT JOIN `serveasy-company` c ON c.provider_id = sp.id ORDER BY sp.id DESC")->fetchAll(PDO::FETCH_ASSOC);
        elseif ($type === 'user')
            $rows = $pdo->query("SELECT * FROM site_user ORDER BY id DESC")->fetchAll(PDO::FETCH_ASSOC);
        elseif ($type === 'verification')
            $rows = $pdo->query("SELECT iv.*, COALESCE(pp.full_name, su.full_name, 'Service Provider') as full_name, COALESCE(sp.email, su.email_address) as email_address, COALESCE(sp.phone, su.phone_number) as phone_number, IF(sp.id IS NOT NULL, 'provider', 'user') as user_role FROM id_verifications iv LEFT JOIN site_user su ON iv.user_id = su.id LEFT JOIN `serveasy-providers` sp ON iv.user_id = sp.id LEFT JOIN `provider_profiles` pp ON pp.provider_id = sp.id WHERE (sp.id IS NOT NULL OR su.id IS NOT NULL) ORDER BY iv.verification_id DESC")->fetchAll(PDO::FETCH_ASSOC);
        elseif ($type === 'service')
            $rows = $pdo->query("SELECT s.*, COALESCE(c.company_name, pp.full_name, '') as business_name, p.email as email_address, sub.name as subcategory_name FROM `serveasy-services` s JOIN `serveasy-providers` p ON s.provider_id = p.id LEFT JOIN `provider_profiles` pp ON pp.provider_id = p.id LEFT JOIN `serveasy-company` c ON c.provider_id = p.id LEFT JOIN `serveasy-subcategories` sub ON s.subcategory_id = sub.id ORDER BY s.id DESC")->fetchAll(PDO::FETCH_ASSOC);

        $config = [
            'admin' => ['label' => 'Admins', 'icon' => 'fa-user-shield', 'id_col' => 'admin_id'],
            'dealer' => ['label' => 'Service Providers', 'icon' => 'fa-handshake', 'id_col' => 'id'],
            'user' => ['label' => 'Users', 'icon' => 'fa-user', 'id_col' => 'id'],
            'verification' => ['label' => 'ID Verifications', 'icon' => 'fa-id-card', 'id_col' => 'verification_id'],
            'service' => ['label' => 'Services', 'icon' => 'fa-cogs', 'id_col' => 'id'],
            'logo' => ['label' => 'Global Logo Settings', 'icon' => 'fa-image', 'id_col' => '']
        ];
        $c = $config[$type];
        ?>
        <style>
            .list-heading {
                font-size: 1.5rem;
                font-weight: 800;
                color: #ffffff;
                margin-bottom: 1.2rem;
                letter-spacing: -0.01em;
            }

            .list-card {
                border: var(--se-glass-border) !important;
                border-radius: var(--se-radius-card) !important;
                background: var(--se-glass-bg) !important;
                backdrop-filter: var(--se-glass-blur) !important;
                -webkit-backdrop-filter: var(--se-glass-blur) !important;
                box-shadow: var(--se-glass-shadow) !important;
                overflow: hidden !important;
                position: relative !important;
            }

            .list-card .card-header {
                background: rgba(255, 255, 255, 0.035) !important;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
                padding: .9rem 1.4rem;
                font-size: .95rem;
                font-weight: 700;
                color: #ffffff !important;
            }

            .green-table thead tr {
                background: rgba(255, 255, 255, 0.035) !important;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            }

            .green-table thead th {
                border: none;
                font-size: .75rem;
                font-weight: 700;
                letter-spacing: .06em;
                text-transform: uppercase;
                padding: .85rem 1rem;
                color: #94a3b8 !important;
                text-align: left !important;
            }

            .green-table tbody tr {
                cursor: pointer;
                background: transparent;
                border-bottom: 1px solid rgba(255, 255, 255, 0.04);
                transition: background .15s ease;
            }

            .green-table tbody tr:hover {
                background: rgba(255, 255, 255, 0.05) !important;
            }

            .green-table tbody td {
                vertical-align: middle;
                font-size: .88rem;
                padding: .75rem 1rem;
                border-color: rgba(255, 255, 255, 0.04) !important;
                color: #e2e8f0 !important;
                text-align: left !important;
            }

            .perm-switch {
                transform: scale(.75);
                margin: 0;
            }
        


.doc-thumb-img {
    transition: transform 0.25s ease, filter 0.25s ease;
    cursor: zoom-in;
    aspect-ratio: auto !important;
    object-fit: contain !important;
}

.doc-preview-wrapper:hover .doc-thumb-img {
    transform: scale(1.06);
    filter: brightness(1.12);
}

</style>
        <h1 class="list-heading"><i class="fas <?= $c['icon'] ?> mr-2" style="color: var(--se-accent-blue, #007aff);"></i><?= $c['label'] ?></h1>
        <div class="card list-card">
            <div class="card-header d-flex align-items-center"><i class="fas <?= $c['icon'] ?> mr-2" style="opacity: 0.85;"></i><?= $type === 'logo' ? 'Upload Site Logo' : $c['label'] . ' List' ?></div>
            <div class="card-body <?= $type === 'logo' ? 'p-4' : 'p-0' ?>">
                <?php if ($type === 'logo'): ?>
                    <?php if (isset($_SESSION['logo_upload_status'])): ?>
                        <?php if ($_SESSION['logo_upload_status'] === 'success'): ?>
                            <div class="alert alert-success">Logo uploaded successfully! The changes are now active globally.</div>
                        <?php else: ?>
                            <div class="alert alert-danger">Error: <?= htmlspecialchars($_SESSION['logo_upload_msg'] ?? 'Upload failed.') ?></div>
                        <?php endif; ?>
                        <?php 
                        unset($_SESSION['logo_upload_status']);
                        unset($_SESSION['logo_upload_msg']);
                        ?>
                    <?php endif; ?>

                    <form method="POST" action="superadmin-dashboard.php" enctype="multipart/form-data">
                        <input type="hidden" name="action" value="upload_logo">
                        <div class="form-group mb-4">
                            <label for="logo_file" class="font-weight-bold text-gray-800">Choose PNG Logo File</label>
                            <input type="file" name="logo_file" id="logo_file" accept=".png" class="form-control-file" required>
                            <small class="form-text text-muted">Please upload a valid <strong>PNG</strong> image. Recommended dimensions: max 150px width, 40px height.</small>
                        </div>
                        
                        <div class="form-group mb-4">
                            <label class="font-weight-bold text-gray-800 d-block">Current Global Logo:</label>
                            <div class="p-3 rounded border bg-light d-inline-block">
                                <?php
                                $logoPath = __DIR__ . '/img/logo.png';
                                if (file_exists($logoPath)) {
                                    echo '<img src="img/logo.png?t=' . time() . '" alt="Site Logo" style="max-height: 45px; width: auto; display: block;">';
                                } else {
                                    echo '<span class="text-muted font-italic">Default Text Logo (ServEasy)</span>';
                                }
                                ?>
                            </div>
                        </div>

                        <button type="submit" class="btn btn-emerald px-4 font-weight-bold" style="background: #05c279; color: #fff;">
                            <i class="fas fa-upload mr-2"></i> Upload Logo
                        </button>
                    </form>
                <?php else: ?>
                    <div class="table-responsive">
                    <table class="table green-table mb-0">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th><?= $type === 'verification' ? 'Contact Details' : ($type === 'service' ? 'Provider Name' : (in_array($type, ['user', 'dealer']) ? 'Phone / Email' : 'Email')) ?></th>
                                <th><?= $type === 'verification' ? 'ID Details' : ($type === 'service' ? 'Category' : ($type === 'dealer' ? 'Company / Type' : 'Role')) ?></th>
                                <th><?= $type === 'verification' ? 'Submitted' : ($type === 'service' ? 'Created At' : (in_array($type, ['user', 'dealer']) ? 'Joined' : 'Last Login')) ?></th>
                                <th>Status</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php if (empty($rows)): ?>
                                <tr>
                                    <td colspan="7" class="text-center py-4 text-muted">No <?= strtolower($c['label']) ?> found.
                                    </td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($rows as $row):
                                    $is_site_user = ($type === 'user');
                                    $is_verification = ($type === 'verification');
                                    $is_service = ($type === 'service');
                                    
                                    if ($is_verification) {
                                        $rid = (int)($row['verification_id'] ?? 0);
                                        $name = htmlspecialchars($row['full_name'] ?? 'User');
                                        $contact = htmlspecialchars(($row['phone_number'] ?: '') . ' / ' . ($row['email_address'] ?: ''));
                                        $prim_text = strtoupper(str_replace('_', ' ', $row['id_type'])) . ': ' . $row['id_number'];
                                        $id_details = '<span class="badge badge-primary px-2.5 py-1" style="font-size:0.75rem; font-weight:600;" title="Primary ID"><i class="fas fa-id-card mr-1"></i> ' . htmlspecialchars($prim_text) . '</span>';
                                        $time = htmlspecialchars($row['created_at']);
                                        $status = htmlspecialchars($row['verification_status']);
                                    } elseif ($is_service) {
                                        $rid = $row['id'];
                                        $name = htmlspecialchars($row['name'] ?? 'Service');
                                        $contact = htmlspecialchars($row['business_name'] ?? 'Unknown');
                                        $id_details = htmlspecialchars($row['subcategory_name'] ?? 'N/A');
                                        $time = htmlspecialchars($row['created_at'] ?? 'N/A');
                                        $status = htmlspecialchars($row['approval_status'] ?? 'pending');
                                    } elseif ($type === 'dealer') {
                                        $rid = $row['id'];
                                        $name = htmlspecialchars($row['full_name'] ?? $row['company_name'] ?? 'Service Provider');
                                        $contact = htmlspecialchars(($row['phone_number'] ?: '') . ' / ' . ($row['email_address'] ?: ''));
                                        $id_details = htmlspecialchars($row['company_name'] ?: 'Individual Provider');
                                        $time = htmlspecialchars($row['created_at'] ?? 'N/A');
                                        $status = !empty($row['is_active']) ? 'active' : 'inactive';
                                        $v_status = $row['verified_status'] ?? 'pending';

                                        // Dynamic Profile Completion Calculation (4 pillars x 25%)
                                        $profile_pct = 0;
                                        if (!empty($row['phone_number']) && strlen(preg_replace('/[^0-9]/', '', $row['phone_number'])) >= 10) {
                                            $profile_pct += 25;
                                        }
                                        if (!empty($row['email_address']) && filter_var($row['email_address'], FILTER_VALIDATE_EMAIL) !== false) {
                                            $profile_pct += 25;
                                        }
                                        if (!empty($row['location_address']) && strlen(trim($row['location_address'])) >= 5) {
                                            $profile_pct += 25;
                                        }
                                        if ($v_status === 'approved' || ($row['latest_verification_status'] ?? '') === 'approved') {
                                            $profile_pct += 25;
                                        }
                                    } elseif ($type === 'user') {
                                        $rid = $row['id'];
                                        $name = htmlspecialchars($row['full_name'] ?? 'User');
                                        $contact = htmlspecialchars(($row['phone_number'] ?: '') . ' / ' . ($row['email_address'] ?: ''));
                                        $id_details = 'User';
                                        $time = htmlspecialchars($row['created_at'] ?? 'N/A');
                                        $status = !empty($row['is_active']) ? 'active' : 'inactive';
                                    } else {
                                        $rid = $row['admin_id'];
                                        $name = htmlspecialchars($row['full_name'] ?? $row['username']);
                                        $contact = htmlspecialchars($row['email'] ?? 'N/A');
                                        $id_details = htmlspecialchars(ucfirst($row['role'] ?? $type));
                                        $time = htmlspecialchars($row['last_login_time'] ?? 'N/A');
                                        $status = htmlspecialchars($row['status'] ?? 'pending');
                                    }
                                    ?>
                                    <tr <?= ($rid > 0) ? 'onclick="loadDetail(\'' . $type . '\', ' . $rid . ')"' : '' ?> style="<?= ($rid > 0) ? 'cursor:pointer;' : '' ?>">
                                        <td><span class="id-badge">#<?= htmlspecialchars($rid) ?></span></td>
                                        <td>
                                            <div class="d-flex align-items-center">
                                                <div class="icon-circle mr-3">
                                                    <i class="fas <?= $c['icon'] ?>"></i>
                                                </div>
                                                <div class="d-flex align-items-center flex-wrap" style="gap: 8px;">
                                                    <span class="font-weight-bold"><?= htmlspecialchars($name) ?></span>
                                                    <?php if ($is_verification): ?>
                                                        <span class="badge badge-emerald" style="font-size:0.65rem;padding:3px 8px;"><?= strtoupper($row['user_role']) ?></span>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </td>
                                        <td><?= htmlspecialchars($contact) ?></td>
                                        <td>
                                            <?php if ($is_verification): ?>
                                                <?= $id_details ?>
                                            <?php else: ?>
                                                <span class="badge badge-emerald"><?= $id_details ?></span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-nowrap" style="white-space: nowrap; font-size: 0.82rem; color: #94a3b8;"><?= htmlspecialchars($time) ?></td>
                                        <td>
                                            <?php 
                                            if ($type === 'dealer') {
                                                $v_class = ($v_status === 'approved') ? 'success' : (($v_status === 'rejected') ? 'danger' : 'warning');
                                                $v_text = ($v_status === 'approved') ? 'Approved' : (($v_status === 'rejected') ? 'Rejected' : 'Under Review');
                                            ?>
                                                <span class="badge badge-<?= $v_class ?> mr-1"><?= $v_text ?></span>
                                                <span class="badge badge-<?= $status === 'active' ? 'success' : 'secondary' ?>"><?= ucfirst($status) ?></span>
                                            <?php 
                                            } else {
                                                if ($is_verification || $is_service) {
                                                    $sc = ($status === 'approved') ? 'success' : (($status === 'pending' || $status === 'under_review') ? 'warning' : 'danger');
                                                } elseif ($type === 'user') {
                                                    $sc = ($status === 'active') ? 'success' : 'danger';
                                                } else {
                                                    $sc = ($status === 'approved') ? 'success' : (($status === 'pending') ? 'warning' : 'secondary');
                                                }
                                                $sl = ucfirst(str_replace('_', ' ', $status)); 
                                            ?>
                                                <span class="badge badge-<?= $sc ?>"><?= $sl ?></span>
                                            <?php } ?>
                                        </td>
 
                                        <td onclick="event.stopPropagation()" style="white-space: nowrap;">
                                            <?php if ($is_verification): ?>
                                                <?php if ($rid > 0): ?>
                                                    <button type="button" class="btn btn-outline-emerald btn-sm font-weight-bold" style="border-width:2px;border-radius:6px;" onclick="loadDetail('verification', <?= $rid ?>)">Review</button>
                                                <?php else: ?>
                                                    <span class="badge badge-secondary py-1 px-2" style="font-size:0.75rem;">Not Submitted</span>
                                                <?php endif; ?>
                                            <?php elseif ($is_service): ?>
                                                <form class="mb-0">
                                                    <input type="hidden" name="toggle_service_id" value="<?= $rid ?>">
                                                    <input type="hidden" name="new_service_status"
                                                        value="<?= $status === 'approved' ? 'pending' : 'approved' ?>">
                                                    <button type="button"
                                                        class="btn <?= $status === 'approved' ? 'btn-outline-danger' : 'btn-outline-success' ?> btn-sm font-weight-bold"
                                                        style="border-width:2px;border-radius:6px;"
                                                        onclick="submitToggleForm(this)"><?= $status === 'approved' ? 'Suspend' : 'Accept' ?></button>
                                                    <button type="button" class="btn btn-outline-emerald btn-sm font-weight-bold ml-1" style="border-width:2px;border-radius:6px;" onclick="loadDetail('service', <?= $rid ?>)">View</button>
                                                </form>
                                            <?php elseif ($type === 'dealer'): ?>
                                                <div class="d-flex align-items-center flex-nowrap" style="gap: 5px;">
                                                    <?php if ($v_status === 'approved'): ?>
                                                        <button type="button" class="btn btn-outline-info btn-sm font-weight-bold text-nowrap"
                                                            style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem; white-space: nowrap;"
                                                            title="View Listed Services"
                                                            onclick="event.stopPropagation(); loadProviderServices(<?= $rid ?>)">
                                                            <i class="fas fa-wrench mr-1"></i> Services
                                                        </button>
                                                    <?php elseif (!empty($row['latest_verification_id']) && (int)$row['latest_verification_id'] > 0): ?>
                                                        <button type="button" class="btn btn-outline-primary btn-sm font-weight-bold text-nowrap"
                                                            style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem; white-space: nowrap;"
                                                            title="Review ID Verification Request #<?= (int)$row['latest_verification_id'] ?>"
                                                            onclick="event.stopPropagation(); loadDetail('verification', <?= (int)$row['latest_verification_id'] ?>)">
                                                            <i class="fas fa-id-card mr-1"></i> ID Request
                                                        </button>
                                                    <?php else: ?>
                                                         <?php 
                                                         $pct_color = ($profile_pct >= 100) ? 'text-success' : (($profile_pct >= 50) ? 'text-info' : 'text-warning');
                                                         ?>
                                                         <span class="badge border <?= $pct_color ?> font-weight-bold text-nowrap"
                                                             style="font-size:0.75rem; padding: 4px 8px; border-radius:6px; background: rgba(255, 255, 255, 0.06); border: 1px solid rgba(255, 255, 255, 0.12); backdrop-filter: blur(8px); white-space: nowrap;"
                                                             title="Profile <?= $profile_pct ?>% Complete">
                                                             <i class="fas fa-chart-pie mr-1"></i><?= $profile_pct ?>%
                                                         </span>
                                                    <?php endif; ?>
                                                    <?php if ($v_status !== 'approved'): ?>
                                                        <button type="button" class="btn btn-outline-success btn-sm font-weight-bold text-nowrap"
                                                            style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem; white-space: nowrap;"
                                                            title="Approve Service Provider"
                                                            onclick="submitDealerVerification(this, <?= $rid ?>, 'approved')">
                                                            <i class="fas fa-check mr-1"></i> Approve
                                                        </button>
                                                    <?php endif; ?>
                                                    <?php if ($v_status !== 'rejected'): ?>
                                                        <button type="button" class="btn btn-outline-danger btn-sm font-weight-bold text-nowrap"
                                                            style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem; white-space: nowrap;"
                                                            title="Reject Service Provider"
                                                            onclick="submitDealerVerification(this, <?= $rid ?>, 'rejected')">
                                                            <i class="fas fa-times mr-1"></i> Reject
                                                        </button>
                                                    <?php endif; ?>

                                                </div>
                                            <?php elseif ($type === 'user'): ?>
                                                <form class="mb-0">
                                                    <input type="hidden" name="toggle_user_id" value="<?= $rid ?>">
                                                    <input type="hidden" name="new_user_status"
                                                        value="<?= $status === 'active' ? 'inactive' : 'active' ?>">
                                                    <button type="button"
                                                        class="btn <?= $status === 'active' ? 'btn-outline-danger' : 'btn-outline-success' ?> btn-sm font-weight-bold"
                                                        style="border-width:2px;border-radius:6px;"
                                                        onclick="submitToggleForm(this)"><?= $status === 'active' ? 'Deactivate' : 'Activate' ?></button>
                                                </form>
                                            <?php else: ?>
                                                <form class="mb-0">
                                                    <input type="hidden" name="toggle_member_id" value="<?= $rid ?>">
                                                    <input type="hidden" name="new_member_status"
                                                        value="<?= $status === 'approved' ? 'pending' : 'approved' ?>">
                                                    <button type="button"
                                                        class="btn <?= $status === 'approved' ? 'btn-outline-danger' : 'btn-outline-success' ?> btn-sm font-weight-bold"
                                                        style="border-width:2px;border-radius:6px;"
                                                        onclick="submitToggleForm(this)"><?= $status === 'approved' ? 'Suspend' : 'Approve' ?></button>
                                                </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                        </tbody>
                    </table>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
        exit();
    }

    // ── AJAX HANDLER FOR DETAILS (GET & POST) ─────────────────────────
    if (!function_exists('resolveDocUrl')) {
    function resolveDocUrl($path) {
        if (empty($path)) return '';
        $path = trim($path);
        if (preg_match('#^https?://#i', $path) || str_starts_with($path, '//') || str_starts_with($path, 'data:')) {
            return $path;
        }
        $clean = preg_replace('#^(\.\./)+#', '', $path);
        $clean = preg_replace('#^(\./)+#', '', $clean);
        $clean = ltrim($clean, '/');

        $httpHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $isLocal = in_array($httpHost, ['localhost', '127.0.0.1', '::1']) || str_starts_with($httpHost, 'localhost:');
        if (!$isLocal) {
            return 'https://beige-curlew-610555.hostingersite.com/backend/' . $clean;
        }
        return '../../' . $clean;
    }
}

    if (isset($_REQUEST['ajax_action']) && $_REQUEST['ajax_action'] === 'fetch_detail') {
        $type = $_REQUEST['type'] ?? 'admin';
        if (!in_array($type, ['admin', 'dealer', 'user', 'verification', 'service']))
            $type = 'admin';
        if (!$is_super_admin && empty($_SESSION['permissions'][$type]) && !in_array($type, ['admin', 'verification', 'service'])) {
            echo 'Access denied.';
            exit();
        }
        if (!$is_super_admin && in_array($type, ['verification', 'service']) && empty($_SESSION['permissions']['dealer'])) {
            echo 'Access denied.';
            exit();
        }
        if (!$is_super_admin && $type === 'admin') {
            echo 'Access denied.';
            exit();
        }

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            if ($type === 'dealer') {
                if (isset($_POST['toggle_dealer_verification_id'], $_POST['new_verification_status'])) {
                    $dealer_id = (int) $_POST['toggle_dealer_verification_id'];
                    $new_status = $_POST['new_verification_status']; // 'approved' or 'rejected'
                    $rej_reason = trim($_POST['rejection_reason'] ?? '');
                    $admin_id = $_SESSION['admin_id'] ?? null;

                    if ($dealer_id && in_array($new_status, ['approved', 'rejected'])) {
                        $active_val = ($new_status === 'approved') ? 1 : 0;
                        $pdo->prepare("UPDATE `serveasy-providers` SET verified_status = ?, is_active = ? WHERE id = ?")->execute([$new_status, $active_val, $dealer_id]);

                        $v_check = $pdo->prepare("SELECT verification_id FROM id_verifications WHERE user_id = ? ORDER BY verification_id DESC LIMIT 1");
                        $v_check->execute([$dealer_id]);
                        $v_id = $v_check->fetchColumn();
                        if ($v_id) {
                            $pdo->prepare("UPDATE id_verifications SET verification_status = ?, rejection_reason = ?, verified_by = ?, verified_at = NOW() WHERE verification_id = ?")->execute([$new_status, ($new_status === 'rejected' && $rej_reason) ? $rej_reason : null, $admin_id, $v_id]);
                        }
                        header('Content-Type: application/json');
                        echo json_encode(['ok' => true, 'message' => "Service provider successfully " . ($new_status === 'approved' ? 'approved' : 'rejected') . "!"]);
                        exit();
                    }
                }
                if (isset($_POST['toggle_dealer_id'], $_POST['new_dealer_status'])) {
                    $st = $_POST['new_dealer_status'];
                    if (in_array($st, ['active', 'inactive'])) {
                        $val = $st === 'active' ? 1 : 0;
                        $pdo->prepare("UPDATE `serveasy-providers` SET is_active=? WHERE id=?")->execute([$val, (int) $_POST['toggle_dealer_id']]);
                    }
                }
                if (isset($_POST['action']) && $_POST['action'] === 'save_edit') {
                    $id = (int)($_POST['id'] ?? 0);
                    $full_name    = $_POST['full_name'] ?? '';
                    $phone_number = $_POST['phone_number'] ?? '';
                    $email_address = $_POST['email_address'] ?? '';
                    $pdo->prepare("UPDATE `serveasy-providers` SET full_name=?, phone=?, email=? WHERE id=?")->execute([$full_name, $phone_number, $email_address, $id]);
                }
                if (isset($_POST['action']) && $_POST['action'] === 'delete_record') {
                    $id = (int)($_POST['id'] ?? 0);
                    $pdo->prepare("DELETE FROM `serveasy-providers` WHERE id=?")->execute([$id]);
                }
            } elseif ($type === 'user') {
                if (isset($_POST['toggle_user_id'], $_POST['new_user_status'])) {
                    $st = $_POST['new_user_status'];
                    if (in_array($st, ['active', 'inactive'])) {
                        $val = $st === 'active' ? 1 : 0;
                        $pdo->prepare("UPDATE site_user SET is_active=? WHERE id=?")->execute([$val, (int) $_POST['toggle_user_id']]);
                    }
                }
                if (isset($_POST['action']) && $_POST['action'] === 'save_edit') {
                    $id = (int)($_POST['id'] ?? 0);
                    $full_name = $_POST['full_name'] ?? '';
                    $phone_number = $_POST['phone_number'] ?? '';
                    $email_address = $_POST['email_address'] ?? '';
                    $pdo->prepare("UPDATE site_user SET full_name=?, phone_number=?, email_address=? WHERE id=?")->execute([$full_name, $phone_number, $email_address, $id]);
                }
                if (isset($_POST['action']) && $_POST['action'] === 'delete_record') {
                    $id = (int)($_POST['id'] ?? 0);
                    $pdo->prepare("DELETE FROM site_user WHERE id=?")->execute([$id]);
                }
            } elseif ($type === 'verification') {
                $v_id = (int)($_POST['verification_id'] ?? 0);
                $status_input = $_POST['verification_status'] ?? ''; // 'approved' or 'rejected'
                $rej_reason = $_POST['rejection_reason'] ?? null;
                $notes = $_POST['admin_notes'] ?? null;
                
                if ($v_id && in_array($status_input, ['approved', 'rejected'])) {
                    $upd_stmt = $pdo->prepare("
                        UPDATE id_verifications 
                        SET verification_status = ?, 
                            rejection_reason = ?, 
                            admin_notes = ?, 
                            verified_by = ?, 
                            verified_at = NOW() 
                        WHERE verification_id = ?
                    ");
                    $upd_stmt->execute([
                        $status_input, 
                        $status_input === 'rejected' ? $rej_reason : null, 
                        $notes, 
                        $admin_id, 
                        $v_id
                    ]);

                    // Sync verified_status to serveasy-providers if needed
                    $u_stmt = $pdo->prepare("SELECT user_id FROM id_verifications WHERE verification_id = ?");
                    $u_stmt->execute([$v_id]);
                    $uid = $u_stmt->fetchColumn();
                    if ($uid) {
                        $pdo->prepare("UPDATE `serveasy-providers` SET verified_status = ? WHERE id = ?")->execute([$status_input, $uid]);
                    }
                    
                    header('Content-Type: application/json');
                    echo json_encode(['ok' => true]);
                    exit();
                }
            } else {
                if (isset($_POST['toggle_admin_id'], $_POST['new_status'])) {
                    $st = $_POST['new_status'];
                    if (in_array($st, ['approved', 'pending']))
                        $pdo->prepare("UPDATE admin_users SET status=?, approved_by=?, approved_at=NOW() WHERE admin_id=? AND role=?")->execute([$st, $_SESSION['admin_id'] ?? null, (int) $_POST['toggle_admin_id'], $type]);
                }
                if (isset($_POST['permission_admin_id'], $_POST['perm_type'], $_POST['perm_val']) && $is_super_admin) {
                    $pt = $_POST['perm_type'];
                    $ok = ['dealer', 'user'];
                    if (in_array($pt, $ok)) {
                        $pdo->prepare("UPDATE admin_users SET can_access_{$pt}=? WHERE admin_id=? AND role!='super_admin'")->execute([$_POST['perm_val'] ? 1 : 0, (int) $_POST['permission_admin_id']]);
                        header('Content-Type: application/json');
                        echo json_encode(['ok' => true, 'perm_type' => $pt, 'perm_val' => (int)$_POST['perm_val']]);
                        exit();
                    }
                }
                if (isset($_POST['action']) && $_POST['action'] === 'save_edit') {
                    $id = (int)($_POST['id'] ?? 0);
                    $full_name = $_POST['full_name'] ?? '';
                    $username = $_POST['username'] ?? '';
                    $email = $_POST['email'] ?? '';
                    $pdo->prepare("UPDATE admin_users SET full_name=?, username=?, email=? WHERE admin_id=? AND role=?")->execute([$full_name, $username, $email, $id, $type]);
                    header('Content-Type: application/json');
                    echo json_encode(['ok' => true]);
                    exit();
                }
                if (isset($_POST['action']) && $_POST['action'] === 'delete_record') {
                    $id = (int)($_POST['id'] ?? 0);
                    // Prevent deleting super_admin
                    $pdo->prepare("DELETE FROM admin_users WHERE admin_id=? AND role=? AND role!='super_admin'")->execute([$id, $type]);
                }
            }
            header('Content-Type: application/json');
            echo json_encode(['ok' => true]);
            exit();
        }

        $id = (int) ($_GET['id'] ?? 0);
        $edit_mode = isset($_GET['edit_mode']) && $_GET['edit_mode'] === '1';
        if ($id <= 0) {
            echo '<div class="text-center py-5 my-4">
                <div class="mb-3 text-warning"><i class="fas fa-exclamation-circle fa-3x"></i></div>
                <h5 class="text-white font-weight-bold">No Valid Item Selected</h5>
                <p class="text-muted small">Please select an entry from the list to view full details.</p>
                <button type="button" class="btn btn-outline-primary btn-sm px-3 mt-2" onclick="loadSection(\'' . htmlspecialchars($type) . '\')">
                    <i class="fas fa-arrow-left mr-1"></i> Back to ' . htmlspecialchars(ucfirst($type)) . ' List
                </button>
            </div>';
            exit();
        }

        $is_verification = ($type === 'verification');
        $is_dealer = ($type === 'dealer');
        $is_site_user = ($type === 'user');
        $is_service = ($type === 'service');
        $ver_info = null;

        if ($is_verification) {
            $stmt = $pdo->prepare("SELECT v.*, COALESCE(pp.full_name, u.full_name, 'Service Provider') as full_name, COALESCE(sp.email, u.email_address) as email_address, COALESCE(sp.phone, u.phone_number) as phone_number, IF(sp.id IS NOT NULL, 'Service Provider', 'User') as user_role, a.username as approved_by_name FROM id_verifications v LEFT JOIN site_user u ON v.user_id = u.id LEFT JOIN `serveasy-providers` sp ON v.user_id = sp.id LEFT JOIN `provider_profiles` pp ON pp.provider_id = sp.id LEFT JOIN admin_users a ON v.verified_by = a.admin_id WHERE v.verification_id = ?");
            $stmt->execute([$id]);
            $ver = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$ver) {
                echo '<div class="text-center py-5 my-4">
                    <div class="mb-3 text-warning"><i class="fas fa-search fa-3x"></i></div>
                    <h5 class="text-white font-weight-bold">Verification Request #' . (int)$id . ' Not Found</h5>
                    <p class="text-muted small">The requested verification record may have been removed or does not exist.</p>
                    <button type="button" class="btn btn-outline-primary btn-sm px-3 mt-2" onclick="loadSection(\'verification\')">
                        <i class="fas fa-arrow-left mr-1"></i> Back to Verification List
                    </button>
                </div>';
                exit();
            }
            $status = $ver['verification_status'];
            $statusBadge = $status === 'approved' ? 'badge-success' : ($status === 'rejected' ? 'badge-danger' : 'badge-warning');
            $role = $ver['user_role'] ?? 'User';
            $name = htmlspecialchars($ver['full_name'] ?? $ver['email_address'] ?? $ver['phone_number'] ?? 'User');
        } elseif ($is_dealer) {
            $stmt = $pdo->prepare("SELECT sp.*, COALESCE(pp.full_name, 'Service Provider') AS full_name, sp.email as email_address, sp.phone as phone_number, COALESCE(c.company_name, '') as company_name FROM `serveasy-providers` sp LEFT JOIN `provider_profiles` pp ON pp.provider_id = sp.id LEFT JOIN `serveasy-company` c ON c.provider_id = sp.id WHERE sp.id = ? LIMIT 1");
            $stmt->execute([$id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                echo '<p class="text-center text-warning mt-4 py-5">Service provider not found.</p>';
                exit();
            }
            $status = !empty($user['is_active']) ? 'active' : 'inactive';
            $statusBadge = $status === 'active' ? 'badge-success' : 'badge-danger';
            $role = 'Service Provider';
            $name = htmlspecialchars($user['full_name'] ?? $user['company_name'] ?? 'Service Provider');
            $admin = $user;
            $admin['admin_id'] = $user['id']; // map for html template

            $v_stmt = $pdo->prepare("SELECT * FROM id_verifications WHERE user_id = ? ORDER BY verification_id DESC LIMIT 1");
            $v_stmt->execute([$user['id']]);
            $ver_doc = $v_stmt->fetch(PDO::FETCH_ASSOC);
            if ($ver_doc) {
                $ver_info = $ver_doc;
            } else {
                $ver_info = ['verification_status' => $user['verified_status'] ?? 'pending', 'verification_id' => 0];
            }
        } elseif ($is_service) {
            $stmt = $pdo->prepare("SELECT s.*, COALESCE(c.company_name, pp.full_name, '') as business_name, p.email as email_address, sub.name as subcategory_name FROM `serveasy-services` s JOIN `serveasy-providers` p ON s.provider_id = p.id LEFT JOIN `provider_profiles` pp ON pp.provider_id = p.id LEFT JOIN `serveasy-company` c ON c.provider_id = p.id LEFT JOIN `serveasy-subcategories` sub ON s.subcategory_id = sub.id WHERE s.id = ? LIMIT 1");
            $stmt->execute([$id]);
            $service = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$service) {
                echo '<p class="text-center text-warning mt-4 py-5">Service not found.</p>';
                exit();
            }
            $status = $service['approval_status'] ?? 'pending';
            $statusBadge = $status === 'approved' ? 'badge-success' : ($status === 'rejected' ? 'badge-danger' : 'badge-warning');
            $role = 'Service';
            $name = htmlspecialchars($service['name']);
        } elseif ($is_site_user) {
            $stmt = $pdo->prepare("SELECT * FROM site_user WHERE id = ? LIMIT 1");
            $stmt->execute([$id]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$user) {
                echo '<div class="alert alert-danger m-4">User not found.</div>';
                exit();
            }
            $status = $user['is_active'] ? 'active' : 'inactive';
            $statusBadge = $status === 'active' ? 'badge-success' : 'badge-danger';
            $role = 'User';
            $name = htmlspecialchars($user['full_name'] ?? $user['email_address'] ?? $user['phone_number'] ?? 'User');
            $admin = $user;
            $admin['admin_id'] = $user['id'];
        } else {
            $stmt = $pdo->prepare("SELECT * FROM admin_users WHERE admin_id = ? LIMIT 1");
            $stmt->execute([$id]);
            $admin = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$admin) {
                echo '<p class="text-center text-warning mt-4 py-5">Record not found.</p>';
                exit();
            }
            $status = $admin['status'] ?? 'pending';
            $statusBadge = $status === 'approved' ? 'badge-success' : ($status === 'pending' ? 'badge-warning' : 'badge-secondary');
            $role = ucfirst($admin['role'] ?? $type);
            $name = htmlspecialchars($admin['full_name'] ?? $admin['username'] ?? 'Admin');
        }

        if ($is_verification):
        ?>
            <div class="d-sm-flex align-items-center justify-content-between mb-4">
                <h1 class="h3 mb-0 text-gray-800 font-weight-bold">Verification Request Details</h1>
            </div>
            <div class="row">
                <div class="col-lg-4 mb-4">
                    <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                        <div class="card-body text-center" style="padding: 30px;">
                            <div class="position-relative d-inline-block mb-3">
                                <div class="img-profile rounded-circle bg-emerald text-white d-flex align-items-center justify-content-center mx-auto"
                                     style="width: 100px; height: 100px; font-size: 2.5rem; background: var(--emerald) !important;">
                                    <i class="fas fa-id-card"></i>
                                </div>
                            </div>
                            <h5 class="font-weight-bold text-gray-800 mb-1"><?= htmlspecialchars($ver['full_name']) ?></h5>
                            <p class="text-muted small mb-2">Request ID: #<?= htmlspecialchars($ver['verification_id']) ?></p>
                            <div class="mb-3">
                                <span class="badge badge-emerald px-3 py-1 rounded-pill" style="background:#05c279; color:#fff; font-weight:700;"><?= strtoupper($ver['user_role']) ?></span>
                            </div>
                            <div class="mb-4">
                                <span class="badge <?= $statusBadge ?> px-3 py-2" style="font-size: 0.8rem; font-weight:700;"><?= ucfirst(str_replace('_', ' ', $status)) ?></span>
                            </div>
                            
                            <div class="pt-3 border-top w-100 text-left">
                                <h6 class="font-weight-bold text-emerald mb-3 small text-uppercase" style="letter-spacing: .05em;">Take Action</h6>
                                
                                <?php if ($status !== 'approved'): ?>
                                    <form id="verificationActionForm">
                                        <input type="hidden" name="verification_id" value="<?= $id ?>">
                                        <input type="hidden" name="verification_status" id="verStatusField" value="">
                                        
                                        <div class="form-group mb-3">
                                            <label class="small font-weight-bold text-gray-700">Admin Notes (Optional)</label>
                                            <textarea name="admin_notes" class="form-control form-control-sm" rows="3" placeholder="Enter notes..." style="border-radius: 6px; font-size: 0.8rem;"><?= htmlspecialchars($ver['admin_notes'] ?? '') ?></textarea>
                                        </div>
                                        
                                        <div class="form-group mb-3" id="rejectionReasonBox" style="display: none;">
                                            <label class="small font-weight-bold text-danger">Rejection Reason (Required for Reject)</label>
                                            <textarea name="rejection_reason" id="rejectionReasonField" class="form-control form-control-sm border-danger" rows="3" placeholder="Explain why the documents were rejected..." style="border-radius: 6px; font-size: 0.8rem;"><?= htmlspecialchars($ver['rejection_reason'] ?? '') ?></textarea>
                                        </div>
                                        
                                        <div class="d-grid gap-2 d-flex justify-content-between mt-3" style="gap: 10px;">
                                            <button type="button" class="btn btn-success btn-sm font-weight-bold flex-grow-1" onclick="submitVerificationAction('approved')" style="border-radius: 6px; padding: 8px 12px; background: #1cc88a; border: none; color:#fff;"><i class="fas fa-check mr-1"></i> Approve</button>
                                            <button type="button" class="btn btn-danger btn-sm font-weight-bold flex-grow-1" id="rejectBtn" onclick="prepareRejection()" style="border-radius: 6px; padding: 8px 12px; background: #e74a3b; border: none; color:#fff;"><i class="fas fa-times mr-1"></i> Reject</button>
                                        </div>
                                    </form>
                                    <script>
                                        function prepareRejection() {
                                            let reasonBox = document.getElementById('rejectionReasonBox');
                                            if (reasonBox.style.display === 'none') {
                                                reasonBox.style.display = 'block';
                                                document.getElementById('rejectionReasonField').required = true;
                                                document.getElementById('rejectBtn').innerText = 'Confirm Reject';
                                            } else {
                                                submitVerificationAction('rejected');
                                            }
                                        }
                                        function submitVerificationAction(statusVal) {
                                            if (statusVal === 'rejected') {
                                                let r = document.getElementById('rejectionReasonField').value.trim();
                                                if (r === '') {
                                                    Notify.warning('Please specify a rejection reason.');
                                                    return;
                                                }
                                            }
                                            document.getElementById('verStatusField').value = statusVal;
                                            let formData = $('#verificationActionForm').serialize() + '&ajax_action=fetch_detail&type=verification';
                                            $.post('superadmin-dashboard.php', formData, function(res) {
                                                if(res.ok) {
                                                    Notify.success('Verification successfully updated!');
                                                    loadDetail('verification', <?= $id ?>);
                                                } else {
                                                    Notify.error('Failed to update verification request.');
                                                }
                                            }, 'json').fail(function() {
                                                Notify.error('Server error.');
                                            });
                                        }
                                    </script>
                                <?php else: ?>
                                    <div class="alert alert-success small p-2" style="border-radius: 6px; background-color:#d1fae5; color:#065f46; border:1px solid #a7f3d0;">
                                        <i class="fas fa-check-circle mr-1"></i> Approved by <strong><?= htmlspecialchars($ver['approved_by_name'] ?? 'Admin') ?></strong> on <?= htmlspecialchars($ver['verified_at']) ?>.
                                    </div>
                                    <?php if ($ver['admin_notes']): ?>
                                        <div class="small bg-light p-2 border" style="border-radius: 6px;">
                                            <strong>Admin Notes:</strong><br><?= nl2br(htmlspecialchars($ver['admin_notes'])) ?>
                                        </div>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-8 mb-4">
                    <style>

/* ================= SERVEASY DOCUMENT ZOOM LIGHTBOX MODAL ================= */
.doc-zoom-modal {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 99999999 !important;
    display: none;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.2s ease, visibility 0.2s ease;
    user-select: none;
}
.doc-zoom-modal.active {
    display: flex !important;
    opacity: 1 !important;
    visibility: visible !important;
}
.doc-zoom-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(5, 10, 24, 0.94);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    cursor: zoom-out;
}
.doc-zoom-container {
    position: relative;
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    pointer-events: none;
    z-index: 2;
}
.doc-zoom-header,
.doc-zoom-footer {
    pointer-events: auto;
}
.doc-zoom-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 24px;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
}
.doc-zoom-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: 0.3px;
}
.btn-zoom-action {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.16);
    color: #e2e8f0;
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 0.82rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.18s ease;
    cursor: pointer;
}
.btn-zoom-action:hover {
    background: rgba(5, 194, 121, 0.22);
    border-color: #05c279;
    color: #ffffff;
    transform: translateY(-1px);
}
.btn-zoom-download {
    background: rgba(5, 194, 121, 0.15);
    border-color: rgba(5, 194, 121, 0.4);
    color: #05c279;
}
.btn-zoom-download:hover {
    background: #05c279;
    color: #000;
}
.btn-zoom-close {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: #f87171;
    border-radius: 8px;
    padding: 6px 14px;
    margin-left: 8px;
    transition: all 0.18s ease;
    cursor: pointer;
}
.btn-zoom-close:hover {
    background: #ef4444;
    color: #ffffff;
    transform: scale(1.05);
}
.doc-zoom-stage {
    flex: 1;
    width: 100%;
    height: 100%;
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: auto;
    cursor: grab;
    position: relative;
}
.doc-zoom-stage.panning {
    cursor: grabbing;
}
.doc-zoom-content-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    transform-origin: center center;
    transition: transform 0.08s ease-out;
    will-change: transform;
}
.doc-zoom-content-wrapper img {
    max-width: 90vw;
    max-height: 80vh;
    width: auto !important;
    height: auto !important;
    aspect-ratio: auto !important;
    object-fit: contain !important;
    border-radius: 10px;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7);
    pointer-events: auto;
    cursor: zoom-in;
    transition: filter 0.2s ease;
}
.doc-zoom-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 10px 20px;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(10px);
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    font-size: 0.8rem;
    color: #94a3b8;
}

/* Document Thumbnail Cards in Verifications Detail */
.doc-card-container {
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    background: #0f172a !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
}
.doc-card-container:hover {
    border-color: #05c279 !important;
    transform: translateY(-3px);
    box-shadow: 0 10px 25px rgba(5, 194, 121, 0.2) !important;
}
.doc-preview-wrapper {
    overflow: hidden;
    border-radius: 6px;
    background: #090d16;
    transition: all 0.25s ease;
    cursor: zoom-in;
}
.doc-preview-wrapper:hover .doc-thumb-img {
    transform: scale(1.06);
    filter: brightness(1.12);
}
.doc-thumb-img {
    transition: transform 0.25s ease, filter 0.25s ease;
    cursor: zoom-in;
}

</style>
<div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                        <div class="card-header bg-white border-bottom-0" style="padding: 30px 30px 10px 30px;">
                            <h6 class="m-0 font-weight-bold text-emerald" style="font-size: 1.1rem;">Verification Information</h6>
                        </div>
                        <div class="card-body" style="padding: 10px 30px 30px 30px;">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">User Full Name:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($ver['full_name']) ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Role:</div>
                                <div class="col-sm-8 text-gray-700"><span class="badge badge-emerald text-white px-2 py-1" style="background:#05c279; font-weight:700; border-radius:0 !important;"><?= strtoupper($ver['user_role']) ?></span></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Email Address:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($ver['email_address'] ?: '—') ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Phone Number:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($ver['phone_number'] ?: '—') ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Primary ID Type:</div>
                                <div class="col-sm-8 text-gray-700 font-weight-bold text-uppercase small"><span class="badge badge-light border text-primary px-2 py-1"><i class="fas fa-id-card mr-1"></i> <?= htmlspecialchars(str_replace('_', ' ', $ver['id_type'])) ?></span></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Primary ID Number:</div>
                                <div class="col-sm-8 text-gray-700 font-weight-bold small" style="letter-spacing: 0.5px;"><?= htmlspecialchars($ver['id_number']) ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-info small">Extra ID Type:</div>
                                <div class="col-sm-8 text-gray-700 font-weight-bold text-uppercase small"><span class="badge badge-light border text-info px-2 py-1"><i class="fas fa-file-alt mr-1"></i> <?= htmlspecialchars(str_replace('_', ' ', $ver['extra_document_type'] ?: 'None')) ?></span></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-info small">Extra ID Number:</div>
                                <div class="col-sm-8 text-gray-700 font-weight-bold small" style="letter-spacing: 0.5px;"><?= htmlspecialchars($ver['extra_document_number'] ?: '—') ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Submitted At:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($ver['created_at']) ?></div>
                            </div>
                            <?php if ($ver['verification_status'] === 'rejected'): ?>
                                <hr class="my-1">
                                <div class="row align-items-center py-2 text-danger small">
                                    <div class="col-sm-4 font-weight-bold">Rejection Reason:</div>
                                    <div class="col-sm-8 font-weight-bold"><?= htmlspecialchars($ver['rejection_reason'] ?: 'None specified.') ?></div>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
    
                                        <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                        <div class="card-header bg-white border-bottom-0" style="padding: 20px 30px 5px 30px;">
                            <h6 class="m-0 font-weight-bold text-emerald" style="font-size: 1rem;"><i class="fas fa-folder-open mr-2"></i> Uploaded ID Documents</h6>
                        </div>
                        <div class="card-body" style="padding: 10px 30px 30px 30px;">
                            <div class="row">
                                <!-- ID Front Photo -->
                                <div class="col-md-3 col-sm-6 text-center mb-3">
                                    <div class="card p-2 shadow-sm border doc-card-container" style="border-radius: 8px; height: 100%;">
                                        <div class="small font-weight-bold text-primary mb-2"><i class="fas fa-id-card mr-1"></i> ID Front Photo</div>
                                        <div class="flex-grow-1 d-flex align-items-center justify-content-center" style="background:#090d16; min-height: 140px; overflow:hidden; border-radius:6px;">
                                            <?php if (!empty($ver['id_front_image'])): 
                                                $frontUrl = resolveDocUrl($ver['id_front_image']);
                                                $idTypeTitle = strtoupper(str_replace('_', ' ', $ver['id_type'] ?: 'ID'));
                                            ?>
                                                <div class="doc-preview-wrapper position-relative w-100 h-100 d-flex align-items-center justify-content-center"
                                                     style="cursor: zoom-in; min-height: 140px;"
                                                     onclick="openDocZoomModal('<?= htmlspecialchars($frontUrl, ENT_QUOTES) ?>', 'ID Front Photo (<?= htmlspecialchars($idTypeTitle, ENT_QUOTES) ?>)', 'image')"
                                                     title="Click to view fullscreen">
                                                    <img src="<?= htmlspecialchars($frontUrl) ?>" class="img-fluid doc-thumb-img" style="max-height: 130px; object-fit: contain;" alt="ID Front Photo"
                                                         onerror="if(!this.dataset.retried){this.dataset.retried='1';var el=this;setTimeout(function(){el.src='<?= htmlspecialchars($frontUrl) ?>'+(el.src.indexOf('?')===-1?'?':'&')+'retry='+Date.now();},1500);}">
                                                </div>
                                                <div class="mt-2">
                                                    <button type="button" class="btn btn-xs btn-outline-info font-weight-bold" style="font-size:0.75rem; border-radius:6px;" onclick="event.stopPropagation(); triggerDirectDownload('<?= htmlspecialchars($frontUrl, ENT_QUOTES) ?>', 'ID_Front_Photo_<?= htmlspecialchars($ver['id_number'], ENT_QUOTES) ?>');">
                                                        <i class="fas fa-download mr-1"></i> Download
                                                    </button>
                                                </div>
                                            <?php else: ?>
                                                <span class="text-muted small">No photo uploaded</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>

                                <!-- ID Back Photo -->
                                <div class="col-md-3 col-sm-6 text-center mb-3">
                                    <div class="card p-2 shadow-sm border doc-card-container" style="border-radius: 8px; height: 100%;">
                                        <div class="small font-weight-bold text-primary mb-2"><i class="fas fa-id-card mr-1"></i> ID Back Photo</div>
                                        <div class="flex-grow-1 d-flex flex-column align-items-center justify-content-center" style="background:#090d16; min-height: 140px; overflow:hidden; border-radius:6px; padding: 6px;">
                                            <?php if (!empty($ver['id_back_image'])): 
                                                $backUrl = resolveDocUrl($ver['id_back_image']);
                                                $idTypeTitle = strtoupper(str_replace('_', ' ', $ver['id_type'] ?: 'ID'));
                                            ?>
                                                <div class="doc-preview-wrapper position-relative w-100 h-100 d-flex align-items-center justify-content-center"
                                                     style="cursor: zoom-in; min-height: 140px;"
                                                     onclick="openDocZoomModal('<?= htmlspecialchars($backUrl, ENT_QUOTES) ?>', 'ID Back Photo (<?= htmlspecialchars($idTypeTitle, ENT_QUOTES) ?>)', 'image')"
                                                     title="Click to view fullscreen">
                                                    <img src="<?= htmlspecialchars($backUrl) ?>" class="img-fluid doc-thumb-img" style="max-height: 130px; object-fit: contain;" alt="ID Back Photo"
                                                         onerror="if(!this.dataset.retried){this.dataset.retried='1';var el=this;setTimeout(function(){el.src='<?= htmlspecialchars($backUrl) ?>'+(el.src.indexOf('?')===-1?'?':'&')+'retry='+Date.now();},1500);}">
                                                </div>
                                                <div class="mt-2">
                                                    <button type="button" class="btn btn-xs btn-outline-info font-weight-bold" style="font-size:0.75rem; border-radius:6px;" onclick="event.stopPropagation(); triggerDirectDownload('<?= htmlspecialchars($backUrl, ENT_QUOTES) ?>', 'ID_Back_Photo_<?= htmlspecialchars($ver['id_number'], ENT_QUOTES) ?>');">
                                                        <i class="fas fa-download mr-1"></i> Download
                                                    </button>
                                                </div>
                                            <?php else: ?>
                                                <span class="text-muted small">No photo uploaded</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>

                                <!-- Selfie with ID -->
                                <div class="col-md-3 col-sm-6 text-center mb-3">
                                    <div class="card p-2 shadow-sm border doc-card-container" style="border-radius: 8px; height: 100%;">
                                        <div class="small font-weight-bold text-primary mb-2"><i class="fas fa-camera mr-1"></i> Selfie with ID</div>
                                        <div class="flex-grow-1 d-flex flex-column align-items-center justify-content-center" style="background:#090d16; min-height: 140px; overflow:hidden; border-radius:6px; padding: 6px;">
                                            <?php if (!empty($ver['selfie_image'])): 
                                                $selfieUrl = resolveDocUrl($ver['selfie_image']);
                                            ?>
                                                <div class="doc-preview-wrapper position-relative w-100 h-100 d-flex align-items-center justify-content-center"
                                                     style="cursor: zoom-in; min-height: 140px;"
                                                     onclick="openDocZoomModal('<?= htmlspecialchars($selfieUrl, ENT_QUOTES) ?>', 'Selfie with ID / Verification Photo', 'image')"
                                                     title="Click to view fullscreen">
                                                    <img src="<?= htmlspecialchars($selfieUrl) ?>" class="img-fluid doc-thumb-img" style="max-height: 130px; object-fit: contain;" alt="Selfie with ID"
                                                         onerror="if(!this.dataset.retried){this.dataset.retried='1';var el=this;setTimeout(function(){el.src='<?= htmlspecialchars($selfieUrl) ?>'+(el.src.indexOf('?')===-1?'?':'&')+'retry='+Date.now();},1500);}">
                                                </div>
                                                <div class="mt-2">
                                                    <button type="button" class="btn btn-xs btn-outline-info font-weight-bold" style="font-size:0.75rem; border-radius:6px;" onclick="event.stopPropagation(); triggerDirectDownload('<?= htmlspecialchars($selfieUrl, ENT_QUOTES) ?>', 'Selfie_Verification_<?= htmlspecialchars($ver['id_number'], ENT_QUOTES) ?>');">
                                                        <i class="fas fa-download mr-1"></i> Download
                                                    </button>
                                                </div>
                                            <?php else: ?>
                                                <span class="text-muted small">No photo uploaded</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>

                                <!-- Extra Document -->
                                <div class="col-md-3 col-sm-6 text-center mb-3">
                                    <div class="card p-2 shadow-sm border doc-card-container" style="border-radius: 8px; height: 100%; border-color: rgba(54, 185, 204, 0.4) !important;">
                                        <div class="small font-weight-bold text-info mb-2 text-truncate" title="Extra: <?= htmlspecialchars(strtoupper(str_replace('_', ' ', $ver['extra_document_type'] ?: 'Extra ID'))) ?>">
                                            <i class="fas fa-file-invoice mr-1"></i> <?= htmlspecialchars(strtoupper(str_replace('_', ' ', $ver['extra_document_type'] ?: 'Extra ID'))) ?>
                                        </div>
                                        <div class="flex-grow-1 d-flex align-items-center justify-content-center" style="background:#090d16; min-height: 140px; overflow:hidden; border-radius:6px;">
                                            <?php if (!empty($ver['extra_document_image'])): 
                                                $extraUrl = resolveDocUrl($ver['extra_document_image']);
                                                $ext = strtolower(pathinfo($ver['extra_document_image'], PATHINFO_EXTENSION));
                                                $isPdf = ($ext === 'pdf');
                                                $extraTitle = 'Extra Document (' . strtoupper(str_replace('_', ' ', $ver['extra_document_type'] ?: 'Extra ID')) . ')';
                                            ?>
                                                <div class="doc-preview-wrapper position-relative w-100 h-100 d-flex align-items-center justify-content-center p-2"
                                                     style="cursor: zoom-in; min-height: 140px;"
                                                     onclick="openDocZoomModal('<?= htmlspecialchars($extraUrl, ENT_QUOTES) ?>', '<?= htmlspecialchars($extraTitle, ENT_QUOTES) ?>', '<?= $isPdf ? 'pdf' : 'image' ?>')"
                                                     title="Click to view full document">
                                                    <?php if ($isPdf): ?>
                                                        <div class="text-center">
                                                            <i class="fas fa-file-pdf fa-3x text-danger mb-1"></i>
                                                            <div class="small font-weight-bold text-danger">Open PDF</div>
                                                            <span class="badge badge-dark border mt-1" style="font-size:0.7rem;"><i class="fas fa-eye mr-1"></i> View in Popup</span>
                                                        </div>
                                                    <?php else: ?>
                                                        <img src="<?= htmlspecialchars($extraUrl) ?>" class="img-fluid doc-thumb-img" style="max-height: 130px; object-fit: contain;" alt="Extra Document">
                                                        
                                                    <?php endif; ?>
                                                </div>
                                            <?php else: ?>
                                                <span class="text-muted small">No extra document</span>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php
            elseif ($is_service):
            ?>
            <div class="d-sm-flex align-items-center justify-content-between mb-4">
                <h1 class="h3 mb-0 text-gray-800 font-weight-bold">Service Details</h1>
            </div>
            <div class="row">
                <div class="col-lg-4 mb-4">
                    <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                        <div class="card-body text-center" style="padding: 30px;">
                            <div class="position-relative d-inline-block mb-3">
                                <div class="img-profile rounded-circle bg-emerald text-white d-flex align-items-center justify-content-center mx-auto"
                                     style="width: 100px; height: 100px; font-size: 2.5rem; background: var(--emerald) !important;">
                                    <i class="fas fa-cogs"></i>
                                </div>
                            </div>
                            <h5 class="font-weight-bold text-gray-800 mb-1"><?= htmlspecialchars($service['name']) ?></h5>
                            <p class="text-muted small mb-2">Service ID: #<?= htmlspecialchars($service['id']) ?></p>
                            <div class="mb-3">
                                <span class="badge badge-emerald px-3 py-1 rounded-pill" style="background:#05c279; color:#fff; font-weight:700;"><?= strtoupper(htmlspecialchars($service['subcategory_name'] ?? 'Category')) ?></span>
                            </div>
                            <div class="mb-4">
                                <span class="badge <?= $statusBadge ?> px-3 py-2" style="font-size: 0.8rem; font-weight:700;"><?= ucfirst(str_replace('_', ' ', $status)) ?></span>
                            </div>
                            
                            <div class="pt-3 border-top w-100 text-left">
                                <h6 class="font-weight-bold text-emerald mb-3 small text-uppercase" style="letter-spacing: .05em;">Take Action</h6>
                                <form id="serviceActionForm">
                                    <input type="hidden" name="toggle_service_id" value="<?= $id ?>">
                                    <input type="hidden" name="new_service_status" id="srvStatusField" value="">
                                    <div class="d-grid gap-2 d-flex justify-content-between mt-3" style="gap: 10px;">
                                        <button type="button" class="btn btn-success btn-sm font-weight-bold flex-grow-1" onclick="submitServiceAction('approved')" style="border-radius: 6px; padding: 8px 12px; background: #1cc88a; border: none; color:#fff;" <?= $status === 'approved' ? 'disabled' : '' ?>><i class="fas fa-check mr-1"></i> Accept</button>
                                        <button type="button" class="btn btn-danger btn-sm font-weight-bold flex-grow-1" onclick="submitServiceAction('rejected')" style="border-radius: 6px; padding: 8px 12px; background: #e74a3b; border: none; color:#fff;" <?= $status === 'rejected' ? 'disabled' : '' ?>><i class="fas fa-times mr-1"></i> Reject</button>
                                    </div>
                                </form>
                                <script>
                                    async function submitServiceAction(statusVal) {
                                        if (statusVal === 'rejected') {
                                            if (typeof Notify !== 'undefined' && Notify.confirm) {
                                                const ok = await Notify.confirm('Are you sure you want to reject this service?', {
                                                    title: 'Reject Service',
                                                    confirmText: 'Reject Service',
                                                    cancelText: 'Cancel',
                                                    type: 'danger'
                                                });
                                                if (!ok) return;
                                            }
                                        }
                                        document.getElementById('srvStatusField').value = statusVal;
                                        let formData = $('#serviceActionForm').serialize() + '&ajax_action=fetch_list&type=service';
                                        $.post('superadmin-dashboard.php', formData, function(res) {
                                            if(res.ok) {
                                                Notify.success('Service status successfully updated!');
                                                loadDetail('service', <?= $id ?>);
                                            } else {
                                                Notify.error('Failed to update service status.');
                                            }
                                        }, 'json').fail(function() {
                                            Notify.error('Server error.');
                                        });
                                    }
                                </script>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-8 mb-4">
                    <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                        <div class="card-header bg-white border-bottom-0" style="padding: 30px 30px 10px 30px;">
                            <h6 class="m-0 font-weight-bold text-emerald" style="font-size: 1.1rem;">Service Information</h6>
                        </div>
                        <div class="card-body" style="padding: 10px 30px 30px 30px;">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Service Name:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($service['name']) ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Category:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($service['subcategory_name'] ?? 'N/A') ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Provider Business Name:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($service['business_name'] ?? 'N/A') ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Base Price:</div>
                                <div class="col-sm-8 text-gray-700 small">₹<?= htmlspecialchars(number_format($service['base_price'], 2)) ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Duration (Minutes):</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($service['duration_minutes']) ?> mins</div>
                            </div>
                            <hr class="my-1">
                            <div class="row py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Description:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= nl2br(htmlspecialchars($service['description'] ?? 'No description provided.')) ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Provider Enabled? (Active):</div>
                                <div class="col-sm-8 text-gray-700 small"><?= $service['is_active'] ? '<span class="badge badge-success">Yes</span>' : '<span class="badge badge-secondary">No</span>' ?></div>
                            </div>
                            <hr class="my-1">
                            <div class="row align-items-center py-2">
                                <div class="col-sm-4 font-weight-bold text-gray-800 small">Created At:</div>
                                <div class="col-sm-8 text-gray-700 small"><?= htmlspecialchars($service['created_at']) ?></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <?php
            else:
            ?>
        <div class="d-sm-flex align-items-center justify-content-between mb-4">
            <h1 class="h3 mb-0 text-gray-800"><?= ucfirst($type) ?> Details</h1>
        </div>
        <div class="row">
            <div class="col-lg-4 mb-4">
                <div class="card shadow-sm border-0 mb-4" style="border-radius: 12px;">
                    <div class="card-body text-center" style="padding: 40px 20px;">
                        <div class="position-relative d-inline-block mb-3">
                            <img class="img-profile rounded-circle p-1" src="img/undraw_profile.svg"
                                style="width: 120px; height: 120px; background-color: var(--mint-cream); border: 2px dashed var(--emerald);">
                        </div>
                        <h5 class="font-weight-bold text-gray-800 mb-1"><?= $name ?></h5>
                        <p class="text-muted small mb-1"><?= ucfirst($type) ?> ID: <?= htmlspecialchars($admin['admin_id']) ?>
                        </p>
                        <div class="mb-4"><span class="badge badge-emerald px-3 py-2 rounded-pill"><?= $role ?> Role</span>
                        </div>
                        <?php if ($is_dealer): ?>
                            <?php $d_v_st = $ver_info['verification_status'] ?? 'pending'; ?>
                            <div class="row g-2 justify-content-center mb-4 px-1 w-100" style="margin: 0 auto;">
                                <!-- First row: Accept and Reject -->
                                <div class="col-6 mb-2 px-1">
                                    <button type="button" class="btn btn-block shadow-sm d-flex align-items-center justify-content-center px-2 py-2 text-nowrap"
                                        style="border-radius: 8px; background: #1cc88a; border: none; color: #fff; min-height: 44px; font-weight: 600; font-size: 0.9rem; transition: all 0.2s ease;"
                                        <?= $d_v_st === 'approved' ? 'disabled' : '' ?>
                                        onclick="submitDetailDealerVerification(<?= $admin['admin_id'] ?>, 'approved')">
                                        <i class="fas fa-check mr-2" style="font-size: 0.95rem;"></i>
                                        <span>Accept</span>
                                    </button>
                                </div>
                                <div class="col-6 mb-2 px-1">
                                    <button type="button" class="btn btn-block shadow-sm d-flex align-items-center justify-content-center px-2 py-2 text-nowrap"
                                        style="border-radius: 8px; background: #e74a3b; border: none; color: #fff; min-height: 44px; font-weight: 600; font-size: 0.9rem; transition: all 0.2s ease;"
                                        <?= $d_v_st === 'rejected' ? 'disabled' : '' ?>
                                        onclick="submitDetailDealerVerification(<?= $admin['admin_id'] ?>, 'rejected')">
                                        <i class="fas fa-times mr-2" style="font-size: 0.95rem;"></i>
                                        <span>Reject</span>
                                    </button>
                                </div>
                                <!-- Second row: Message and Services -->
                                <div class="col-6 px-1">
                                    <button type="button" class="btn btn-block shadow-sm d-flex align-items-center justify-content-center px-2 py-2 bg-white text-nowrap"
                                        style="border-radius: 8px; border: 1px solid rgba(0,0,0,0.08); color: #05c279; min-height: 44px; font-weight: 600; font-size: 0.9rem; transition: all 0.2s ease;"
                                        onclick="<?= !empty($admin['email_address']) || !empty($admin['email']) ? "window.location.href='mailto:" . htmlspecialchars($admin['email_address'] ?? $admin['email'] ?? '') . "'" : "if(typeof Notify!=='undefined') Notify.info('No email address available for this provider.');" ?>">
                                        <i class="fas fa-envelope mr-2" style="font-size: 0.95rem; color: #05c279;"></i>
                                        <span>Message</span>
                                    </button>
                                </div>
                                <div class="col-6 px-1">
                                    <button type="button" class="btn btn-block shadow-sm d-flex align-items-center justify-content-center px-2 py-2 bg-white text-nowrap"
                                        style="border-radius: 8px; border: 1px solid rgba(0,0,0,0.08); color: #05c279; min-height: 44px; font-weight: 600; font-size: 0.9rem; transition: all 0.2s ease;"
                                        onclick="loadProviderServices(<?= $admin['admin_id'] ?>)">
                                        <i class="fas fa-wrench mr-2" style="font-size: 0.95rem; color: #05c279;"></i>
                                        <span>Services</span>
                                    </button>
                                </div>
                            </div>
                        <?php else: ?>
                            <div class="d-flex justify-content-center mb-4 flex-wrap" style="gap: 8px;">
                                <button class="btn btn-light btn-sm text-emerald shadow-sm px-3 border-0"><i
                                        class="fas fa-envelope mr-1"></i> Message</button>
                            <?php if ($is_site_user): ?>
                                <form class="mb-0" id="statusForm-<?= $admin['admin_id'] ?>">
                                    <input type="hidden" name="toggle_user_id" value="<?= $admin['admin_id'] ?>">
                                    <input type="hidden" name="new_user_status" value="<?= $status === 'active' ? 'inactive' : 'active' ?>">
                                    <button type="button" class="btn btn-light btn-sm shadow-sm px-4 border-0"
                                        style="color: <?= $status === 'active' ? '#e74a3b' : '#1cc88a' ?>;"
                                        onclick="submitDetailToggle(this, '<?= $type ?>')">
                                        <i class="fas <?= $status === 'active' ? 'fa-ban' : 'fa-check-circle' ?> mr-1"></i><?= $status === 'active' ? 'Deactivate' : 'Activate' ?>
                                    </button>
                                </form>
                            <?php else: ?>
                                <form class="mb-0" id="statusForm-<?= $admin['admin_id'] ?>">
                                    <input type="hidden" name="toggle_admin_id" value="<?= $admin['admin_id'] ?>">
                                    <input type="hidden" name="new_status" value="<?= $status === 'approved' ? 'pending' : 'approved' ?>">
                                    <button type="button" class="btn btn-light btn-sm shadow-sm px-4 border-0"
                                        style="color: <?= $status === 'approved' ? '#e74a3b' : '#1cc88a' ?>;"
                                        onclick="submitDetailToggle(this, '<?= $type ?>')">
                                        <i class="fas <?= $status === 'approved' ? 'fa-ban' : 'fa-check-circle' ?> mr-1"></i><?= $status === 'approved' ? 'Suspend' : 'Approve' ?>
                                    </button>
                                </form>
                            <?php endif; ?>
                            </div>
                        <?php endif; ?>
                        <div class="pt-3 border-top w-100">
                            <div class="row text-center text-gray-700">
                                <div class="col-4 border-right">
                                    <h6 class="font-weight-bold mb-0 text-emerald">#<?= htmlspecialchars($admin['admin_id']) ?>
                                    </h6><small class="text-muted font-weight-bold"
                                        style="font-size: 0.7rem; text-transform: uppercase;">ID</small>
                                </div>
                                <div class="col-4 border-right">
                                    <h6 class="font-weight-bold mb-0 text-emerald"><span class="badge <?= $statusBadge ?>"
                                            style="font-size:.65rem;"><?= ucfirst($status) ?></span></h6><small
                                        class="text-muted font-weight-bold"
                                        style="font-size: 0.7rem; text-transform: uppercase;">Status</small>
                                </div>
                                <div class="col-4">
                                    <h6 class="font-weight-bold mb-0 text-emerald" style="font-size:.85rem;">
                                        <?= !empty($admin['approved_at']) ? date('M y', strtotime($admin['approved_at'])) : 'N/A' ?>
                                    </h6><small class="text-muted font-weight-bold"
                                        style="font-size: 0.7rem; text-transform: uppercase;">Since</small>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-lg-8 mb-4">
                <div class="card shadow-sm border-0 mb-4 h-100" style="border-radius: 12px;">
                    <form id="editForm">
                        <input type="hidden" name="action" value="save_edit">
                        <input type="hidden" name="id" value="<?= $id ?>">
                        <input type="hidden" name="type" value="<?= $type ?>">
                        <div class="card-header d-flex flex-row align-items-center justify-content-between bg-white border-bottom-0"
                            style="padding: 50px 50px 30px 50px; border-top-left-radius: 12px; border-top-right-radius: 12px;">
                            <h6 class="m-0 font-weight-bold text-emerald" style="font-size: 1.1rem;">Account Information</h6>
                            <?php if ($edit_mode): ?>
                                <div>
                                    <button type="button" class="btn btn-emerald btn-sm px-3 mr-1" onclick="saveEdit('<?= $type ?>', <?= $id ?>)">Save</button>
                                    <button type="button" class="btn btn-light btn-sm px-3" onclick="loadDetail('<?= $type ?>', <?= $id ?>)">Cancel</button>
                                </div>
                            <?php else: ?>
                                <a href="#" class="text-emerald font-weight-bold small" style="text-decoration: none;" onclick="toggleEditMode('<?= $type ?>', <?= $id ?>, true); return false;"><i
                                    class="fas fa-pen"></i> Edit</a>
                            <?php endif; ?>
                        </div>
                        <div class="card-body d-flex flex-column justify-content-between" style="padding: 0 50px 30px 50px;">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Full Name:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4">
                                        <?php if ($edit_mode): ?>
                                            <input type="text" name="full_name" class="form-control form-control-sm" value="<?= htmlspecialchars($admin['full_name'] ?? '') ?>">
                                        <?php else: ?>
                                            <?= htmlspecialchars($admin['full_name'] ?? '—') ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800"><?= $type === 'user' ? 'Phone Number:' : 'Username:' ?></div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4">
                                        <?php if ($edit_mode): ?>
                                            <input type="text" name="<?= $type === 'user' ? 'phone_number' : 'username' ?>" class="form-control form-control-sm" value="<?= htmlspecialchars($admin['phone_number'] ?? $admin['username'] ?? '') ?>">
                                        <?php else: ?>
                                            <?= htmlspecialchars($admin['phone_number'] ?? $admin['username'] ?? '—') ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Email Address:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4">
                                        <?php if ($edit_mode): ?>
                                            <input type="email" name="<?= $type === 'user' ? 'email_address' : 'email' ?>" class="form-control form-control-sm" value="<?= htmlspecialchars($admin['email'] ?? $admin['email_address'] ?? '') ?>">
                                        <?php else: ?>
                                            <?= htmlspecialchars($admin['email'] ?? $admin['email_address'] ?? '—') ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <?php if ($type !== 'user'): ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Phone Number:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4">
                                        <?php if ($edit_mode): ?>
                                            <input type="text" name="phone_number" class="form-control form-control-sm" value="<?= htmlspecialchars($admin['phone_number'] ?? '') ?>">
                                        <?php else: ?>
                                            <?= htmlspecialchars($admin['phone_number'] ?? '—') ?>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <?php endif; ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Role:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><span
                                            class="badge badge-emerald px-3 py-1 rounded-pill"><?= $role ?></span></div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Status:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><span
                                            class="badge <?= $statusBadge ?> px-3 py-1"><?= ucfirst($status) ?></span></div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <?php if (in_array($type, ['dealer'])): ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Verification Status:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4 d-flex align-items-center flex-wrap" style="gap: 8px;">
                                        <?php if ($ver_info): 
                                            $v_status = $ver_info['verification_status'];
                                            $v_badge = $v_status === 'approved' ? 'badge-success' : ($v_status === 'rejected' ? 'badge-danger' : 'badge-warning');
                                            $v_label = ucfirst(str_replace('_', ' ', $v_status));
                                        ?>
                                            <span class="badge <?= $v_badge ?> px-3 py-1 mr-2"><?= $v_label ?></span>
                                            <?php if (!empty($ver_info['verification_id']) && (int)$ver_info['verification_id'] > 0): ?>
                                                <button type="button" class="btn btn-outline-emerald btn-xs py-1 px-2 font-weight-bold" style="font-size: 0.75rem; border-radius: 4px; border-width: 1px;" onclick="loadDetail('verification', <?= $ver_info['verification_id'] ?>)">Review Documents</button>
                                            <?php endif; ?>
                                            <?php if ($v_status !== 'approved'): ?>
                                                <button type="button" class="btn btn-success btn-xs py-1 px-2 font-weight-bold" style="font-size: 0.75rem; border-radius: 4px; background:#1cc88a; border:none; color:#fff;" onclick="submitDetailDealerVerification(<?= $admin['admin_id'] ?>, 'approved')"><i class="fas fa-check mr-1"></i> Approve Provider</button>
                                            <?php endif; ?>
                                            <?php if ($v_status !== 'rejected'): ?>
                                                <button type="button" class="btn btn-danger btn-xs py-1 px-2 font-weight-bold" style="font-size: 0.75rem; border-radius: 4px; background:#e74a3b; border:none; color:#fff;" onclick="submitDetailDealerVerification(<?= $admin['admin_id'] ?>, 'rejected')"><i class="fas fa-times mr-1"></i> Reject Provider</button>
                                            <?php endif; ?>
                                        <?php else: ?>
                                            <span class="badge badge-secondary px-3 py-1">Not Submitted</span>
                                        <?php endif; ?>
                                    </div>
                                </div>
                            </div>
                            <?php if (!empty($ver_info['rejection_reason'])): ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-danger">Rejection Reason:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4 text-danger font-weight-bold">
                                        <?= htmlspecialchars($ver_info['rejection_reason']) ?>
                                    </div>
                                </div>
                            </div>
                            <?php endif; ?>
                            <hr class="m-0">
                            
                            <!-- Provider Services -->
                            <?php 
                            $provider_stmt = $pdo->prepare("SELECT id FROM `serveasy-providers` WHERE id = ? LIMIT 1");
                            $provider_stmt->execute([$id]);
                            $provider_id = $provider_stmt->fetchColumn();
                            if ($provider_id):
                                $services_stmt = $pdo->prepare("SELECT * FROM `serveasy-services` WHERE provider_id = ? ORDER BY id DESC");
                                $services_stmt->execute([$provider_id]);
                                $provider_services = $services_stmt->fetchAll(PDO::FETCH_ASSOC);
                            ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-12 font-weight-bold text-gray-800 mb-2">Provider Services:</div>
                                <div class="col-12">
                                    <?php if (empty($provider_services)): ?>
                                        <div class="text-muted small">No services added by this provider.</div>
                                    <?php else: ?>
                                        <div class="table-responsive">
                                            <table class="table green-table mb-0" style="border: 1px solid #eee; border-radius: 8px; overflow: hidden;">
                                                <thead>
                                                    <tr>
                                                        <th>Service Name</th>
                                                        <th>Base Price</th>
                                                        <th>Duration</th>
                                                        <th>Status</th>
                                                        <th>Action</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php foreach ($provider_services as $srv): 
                                                        $srv_status = $srv['approval_status'] ?? 'pending';
                                                    ?>
                                                    <tr onclick="loadDetail('service', <?= $srv['id'] ?>)" style="cursor: pointer;">
                                                        <td><?= htmlspecialchars($srv['name']) ?></td>
                                                        <td class="text-emerald font-weight-bold">₹<?= htmlspecialchars(number_format($srv['base_price'], 2)) ?></td>
                                                        <td><?= htmlspecialchars($srv['duration_minutes']) ?> mins</td>
                                                        <td>
                                                            <span class="badge badge-<?= $srv_status === 'approved' ? 'success' : ($srv_status === 'pending' ? 'warning' : 'danger') ?>">
                                                                <?= ucfirst($srv_status) ?>
                                                            </span>
                                                        </td>
                                                        <td onclick="event.stopPropagation()">
                                                            <form class="mb-0">
                                                                <input type="hidden" name="toggle_service_id" value="<?= $srv['id'] ?>">
                                                                <input type="hidden" name="new_service_status" class="service-status-input" value="">
                                                                <?php if ($srv_status === 'pending'): ?>
                                                                    <button type="button" class="btn btn-outline-success btn-sm font-weight-bold" style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem;" onclick="submitDetailServiceAction(this, 'approved', <?= $id ?>)">Accept</button>
                                                                    <button type="button" class="btn btn-outline-danger btn-sm font-weight-bold ml-1" style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem;" onclick="submitDetailServiceAction(this, 'rejected', <?= $id ?>)">Reject</button>
                                                                <?php elseif ($srv_status === 'approved'): ?>
                                                                    <button type="button" class="btn btn-outline-danger btn-sm font-weight-bold" style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem;" onclick="submitDetailServiceAction(this, 'rejected', <?= $id ?>)">Reject</button>
                                                                <?php else: ?>
                                                                    <button type="button" class="btn btn-outline-success btn-sm font-weight-bold" style="border-width:2px;border-radius:6px; padding: 2px 8px; font-size: 0.75rem;" onclick="submitDetailServiceAction(this, 'approved', <?= $id ?>)">Accept</button>
                                                                <?php endif; ?>
                                                            </form>
                                                        </td>
                                                    </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <hr class="m-0">
                            <script>
                                async function submitDetailServiceAction(btn, action, dealerId) {
                                    if (action === 'rejected') {
                                        if (typeof Notify !== 'undefined' && Notify.confirm) {
                                            const ok = await Notify.confirm('Are you sure you want to reject this service?', {
                                                title: 'Reject Service',
                                                confirmText: 'Reject Service',
                                                cancelText: 'Cancel',
                                                type: 'danger'
                                            });
                                            if (!ok) return;
                                        }
                                    }
                                    let form = $(btn).closest('form');
                                    form.find('.service-status-input').val(action);
                                    let formData = form.serialize() + '&ajax_action=fetch_list&type=service';
                                    $.post('superadmin-dashboard.php', formData, function() {
                                        loadDetail('dealer', dealerId);
                                    });
                                }
                            </script>
                            <?php endif; ?>
                            
                            <?php endif; ?>
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Last Login:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><?= htmlspecialchars($admin['last_login_time'] ?? 'Never') ?>
                                    </div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Approved By:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><?= htmlspecialchars($admin['approved_by'] ?? 'N/A') ?></div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Approved At:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><?= htmlspecialchars($admin['approved_at'] ?? 'N/A') ?></div>
                                </div>
                            </div>
                            <hr class="m-0">
                            <div class="row align-items-center" style="padding: 14px 0;">
                                <div class="col-sm-4 font-weight-bold text-gray-800">Created At:</div>
                                <div class="col-sm-8 d-flex justify-content-center">
                                    <div class="text-left w-100 pl-4"><?= htmlspecialchars($admin['created_at'] ?? 'N/A') ?></div>
                                </div>
                            </div>
                            </div>
                    </form>
                    <div style="padding: 0 50px 30px 50px;">
                            <hr class="mt-4 mb-4">
                            <div class="text-right">
                                <button type="button" class="btn btn-outline-danger btn-sm px-4" onclick="deleteRecord('<?= $type ?>', <?= $id ?>)">
                                    <i class="fas fa-trash-alt mr-1"></i> Delete Account
                                </button>
                            </div>
                        <?php if ($type === 'admin' && $is_super_admin): ?>
                            <hr class="mt-2 mb-3">
                            <div>
                                <h6 class="font-weight-bold text-emerald mb-3"
                                    style="font-size:.85rem; text-transform:uppercase; letter-spacing:.05em;">Module Permissions
                                </h6>
                                <div class="row">
                                    <?php foreach (['dealer', 'user'] as $perm):
                                        $col = 'can_access_' . $perm;
                                        $has = !empty($admin[$col]);
                                        ?>
                                        <div class="col-6 col-md-3 mb-3">
                                            <div class="card border-0 shadow-sm text-center py-3 px-2"
                                                style="border-radius:10px; background:#f8f9fc;">
                                                <div class="mb-2"><i
                                                        class="fas <?= $perm === 'dealer' ? 'fa-handshake' : 'fa-user' ?> fa-lg perm-icon-<?= $perm ?>"
                                                        style="color: <?= $has ? '#05c279' : '#ccc' ?>;"></i></div>
                                                <div class="small font-weight-bold text-gray-700 mb-1"><?= $perm === 'dealer' ? 'Service Provider' : ucfirst($perm) ?></div>
                                                <?php if ($perm === 'dealer'): ?>
                                                    <div class="text-muted small mb-2" style="font-size:0.65rem; margin-top:-2px;">(Includes Services)</div>
                                                <?php else: ?>
                                                    <div class="mb-2"></div>
                                                <?php endif; ?>
                                                <label class="switch mb-0">
                                                    <input type="checkbox" id="perm-switch-<?= $perm ?>-<?= $admin['admin_id'] ?>" <?= $has ? 'checked' : '' ?>
                                                        onchange="submitPermToggle(this, <?= (int)$admin['admin_id'] ?>, '<?= $perm ?>')">
                                                    <span class="slider"></span>
                                                </label>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        <?php endif; ?>
        <?php
        exit();
    }

    // Live counts for KPI cards & topbar
    $cnt_admin = $is_super_admin ? $pdo->query("SELECT COUNT(*) FROM admin_users WHERE role='admin'")->fetchColumn() : 0;
    $cnt_dealer = $pdo->query("SELECT COUNT(*) FROM `serveasy-providers`")->fetchColumn();
    $cnt_user = $pdo->query("SELECT COUNT(*) FROM site_user")->fetchColumn();
    $cnt_verifications = $pdo->query("SELECT COUNT(*) FROM id_verifications iv LEFT JOIN site_user su ON iv.user_id = su.id LEFT JOIN `serveasy-providers` sp ON iv.user_id = sp.id WHERE iv.verification_status='pending' AND (sp.id IS NOT NULL OR su.id IS NOT NULL)")->fetchColumn();
    $cnt_blogs = $pdo->query("SELECT COUNT(*) FROM blog_posts")->fetchColumn();
    $cnt_categories = $pdo->query("SELECT COUNT(*) FROM `serveasy-categories`")->fetchColumn();

} catch (PDOException $e) {
    die("Database error: " . $e->getMessage());
}

// Open tab and id from query params
$open_tab = $_GET['tab'] ?? $_GET['type'] ?? '';
$open_id = isset($_GET['id']) ? (int)$_GET['id'] : 0;
$valid_tabs = ['dealer', 'user', 'verification', 'service', 'logo', 'blogs', 'categories', 'dealer_services'];
if ($is_super_admin)
    $valid_tabs[] = 'admin';
if (!in_array($open_tab, $valid_tabs)) {
    $open_tab = '';
    $open_id = 0;
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <!-- ServEasy Favicon -->
  <link rel="icon" type="image/svg+xml" href="favicon.svg">
  <link rel="alternate icon" type="image/x-icon" href="favicon.ico">
  <link rel="icon" type="image/png" sizes="32x32" href="favicon-32x32.png">
  <link rel="apple-touch-icon" sizes="180x180" href="apple-touch-icon.png">
    <script src="./config.js"></script>
    <script src="./serveasy-api-bridge.js"></script>
    <?php
    $base_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . implode('/', array_map('rawurlencode', explode('/', str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME']))))) . '/';
    ?>
    <base href="<?= $base_url ?>">
    <script>
        setInterval(function () {
            fetch('ping.php').then(r => { if (r.status === 401) window.location.href = 'superadmin-login.php'; }).catch(() => { });
        }, 4000);
    </script>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Dashboard – ServEasy</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css?family=Nunito:400,600,700,800" rel="stylesheet">
    <link href="css/sb-admin-2.min.css" rel="stylesheet">
    <link href="css/super-admin.css?v=21" rel="stylesheet">
    <link rel="stylesheet" href="css/notify.css">
    <style>
        /* ── Toggle switch ─────────────────────── */
        .switch {
            position: relative;
            display: inline-block;
            width: 36px;
            height: 20px;
            margin: 0;
            vertical-align: middle;
        }

        .switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }

        .slider {
            position: absolute;
            cursor: pointer;
            inset: 0;
            background: #e74a3b;
            transition: .3s;
            border-radius: 20px;
        }

        .slider:before {
            position: absolute;
            content: "";
            height: 14px;
            width: 14px;
            left: 3px;
            bottom: 3px;
            background: #fff;
            transition: .3s;
            border-radius: 50%;
        }

        input:checked+.slider {
            background: #1cc88a;
        }

        input:checked+.slider:before {
            transform: translateX(16px);
        }

        /* ── Green-header AJAX table ───────────── */
        .dyn-card {
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 18px !important;
            background: rgba(16, 22, 36, 0.72) !important;
            backdrop-filter: blur(20px) !important;
            -webkit-backdrop-filter: blur(20px) !important;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.45) !important;
            overflow: hidden;
        }

        .dyn-card .card-header {
            background: rgba(255, 255, 255, 0.035) !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08) !important;
            padding: .9rem 1.4rem;
            font-weight: 700;
            color: #ffffff !important;
            font-size: .95rem;
        }

        .green-table thead tr {
            background: rgba(255, 255, 255, 0.035) !important;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }

        .green-table thead th {
            color: #94a3b8 !important;
            border: none;
            font-size: .75rem;
            font-weight: 700;
            letter-spacing: .06em;
            text-transform: uppercase;
            padding: .85rem 1rem;
            text-align: left !important;
        }

        .green-table tbody tr {
            cursor: pointer;
            background: transparent;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
            transition: background .12s ease;
        }

        .green-table tbody tr:hover {
            background: rgba(255, 255, 255, 0.05) !important;
        }

        .green-table tbody td {
            vertical-align: middle;
            font-size: .87rem;
            padding: .7rem 1rem;
            border-color: rgba(255, 255, 255, 0.04) !important;
            color: #e2e8f0 !important;
            text-align: left !important;
        }

        .list-heading {
            font-size: 1.5rem;
            font-weight: 800;
            color: #ffffff !important;
            margin-bottom: 1.2rem;
            letter-spacing: -0.01em;
        }

        /* Spinner */
        #list-spinner {
            display: none;
            text-align: center;
            padding: 3rem 0;
        }

        #list-spinner .spinner-border {
            color: var(--se-accent-blue);
            width: 2.5rem;
            height: 2.5rem;
        }

        /* Sidebar active section */
        #accordionSidebar .nav-item.active-section>a,
        #accordionSidebar .nav-item.active>a {
            background: var(--se-accent-blue-gradient) !important;
            color: #ffffff !important;
            border-radius: var(--se-radius-btn) !important;
            box-shadow: var(--se-accent-blue-glow) !important;
        }

        /* Fade in animation */
        #list-content {
            animation: fadeUp .22s ease;
        }

        @keyframes fadeUp {
            from {
                opacity: 0;
                transform: translateY(10px)
            }

            to {
                opacity: 1;
                transform: translateY(0)
            }
        }
    

/* ================= SERVEASY DOCUMENT ZOOM LIGHTBOX MODAL ================= */
.doc-zoom-modal {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 99999999 !important;
    display: none;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    opacity: 0;
    visibility: hidden;
    transition: opacity 0.2s ease, visibility 0.2s ease;
    user-select: none;
}
.doc-zoom-modal.active {
    display: flex !important;
    opacity: 1 !important;
    visibility: visible !important;
}
.doc-zoom-backdrop {
    position: absolute;
    inset: 0;
    background: rgba(5, 10, 24, 0.94);
    backdrop-filter: blur(14px);
    -webkit-backdrop-filter: blur(14px);
    cursor: zoom-out;
}
.doc-zoom-container {
    position: relative;
    width: 100%;
    height: 100%;
    display: flex;
    flex-direction: column;
    pointer-events: none;
    z-index: 2;
}
.doc-zoom-header,
.doc-zoom-footer {
    pointer-events: auto;
}
.doc-zoom-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 24px;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.12);
}
.doc-zoom-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #f8fafc;
    letter-spacing: 0.3px;
}
.btn-zoom-action {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.16);
    color: #e2e8f0;
    border-radius: 8px;
    padding: 6px 12px;
    font-size: 0.82rem;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: all 0.18s ease;
    cursor: pointer;
}
.btn-zoom-action:hover {
    background: rgba(5, 194, 121, 0.22);
    border-color: #05c279;
    color: #ffffff;
    transform: translateY(-1px);
}
.btn-zoom-download {
    background: rgba(5, 194, 121, 0.15);
    border-color: rgba(5, 194, 121, 0.4);
    color: #05c279;
}
.btn-zoom-download:hover {
    background: #05c279;
    color: #000;
}
.btn-zoom-close {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.4);
    color: #f87171;
    border-radius: 8px;
    padding: 6px 14px;
    margin-left: 8px;
    transition: all 0.18s ease;
    cursor: pointer;
}
.btn-zoom-close:hover {
    background: #ef4444;
    color: #ffffff;
    transform: scale(1.05);
}
.doc-zoom-stage {
    flex: 1;
    width: 100%;
    height: 100%;
    overflow: hidden;
    display: flex;
    align-items: center;
    justify-content: center;
    pointer-events: auto;
    cursor: grab;
    position: relative;
}
.doc-zoom-stage.panning {
    cursor: grabbing;
}
.doc-zoom-content-wrapper {
    display: flex;
    align-items: center;
    justify-content: center;
    transform-origin: center center;
    transition: transform 0.08s ease-out;
    will-change: transform;
}
.doc-zoom-content-wrapper img {
    max-width: 90vw;
    max-height: 80vh;
    width: auto !important;
    height: auto !important;
    aspect-ratio: auto !important;
    object-fit: contain !important;
    border-radius: 10px;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.7);
    pointer-events: auto;
    cursor: zoom-in;
    transition: filter 0.2s ease;
}
.doc-zoom-footer {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 10px 20px;
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(10px);
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    font-size: 0.8rem;
    color: #94a3b8;
}

/* Document Thumbnail Cards in Verifications Detail */
.doc-card-container {
    transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
    background: #0f172a !important;
    border: 1px solid rgba(255, 255, 255, 0.1) !important;
}
.doc-card-container:hover {
    border-color: #05c279 !important;
    transform: translateY(-3px);
    box-shadow: 0 10px 25px rgba(5, 194, 121, 0.2) !important;
}
.doc-preview-wrapper {
    overflow: hidden;
    border-radius: 6px;
    background: #090d16;
    transition: all 0.25s ease;
    cursor: zoom-in;
}
.doc-preview-wrapper:hover .doc-thumb-img {
    transform: scale(1.06);
    filter: brightness(1.12);
}
.doc-thumb-img {
    transition: transform 0.25s ease, filter 0.25s ease;
    cursor: zoom-in;
}

</style>
</head>

<body id="page-top">
    <div id="wrapper">

        <!-- ═══════════════════ SIDEBAR ═══════════════════ -->
        <ul class="navbar-nav sidebar sidebar-dark accordion" id="accordionSidebar">

            <a class="sidebar-brand d-flex align-items-center justify-content-center" href="superadmin-dashboard.php">
                <?php
                $logoPath = __DIR__ . '/img/logo.png';
                if (file_exists($logoPath)) {
                    echo '<img src="img/logo.png?t=' . time() . '" alt="ServEasy Logo" style="max-height: 40px; width: auto; max-width: 85%;">';
                } else {
                    echo '<div class="sidebar-brand-icon rotate-n-15"><i class="fas fa-leaf"></i></div>';
                    echo '<div class="sidebar-brand-text mx-3">ServEasy <sup>' . ($is_super_admin ? 'SA' : 'Admin') . '</sup></div>';
                }
                ?>
            </a>
            <hr class="sidebar-divider my-0">

            <!-- Dashboard -->
            <li class="nav-item" id="nav-home">
                <a class="nav-link" href="#" onclick="showDashboard();return false;">
                    <i class="fas fa-fw fa-tachometer-alt"></i><span>Dashboard</span>
                </a>
            </li>
            <hr class="sidebar-divider">
            <div class="sidebar-heading">Interface</div>

            <!-- Admin — super_admin only -->
            <?php if ($is_super_admin): ?>
                <li class="nav-item" id="nav-admin">
                    <a class="nav-link" href="#" onclick="loadSection('admin');return false;">
                        <i class="fas fa-fw fa-user-shield"></i><span>Admin</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Dealer -->
            <?php if ($is_super_admin || !empty($_SESSION['permissions']['dealer'])): ?>
                <li class="nav-item" id="nav-dealer">
                    <a class="nav-link" href="#" onclick="loadSection('dealer');return false;">
                        <i class="fas fa-fw fa-handshake"></i><span>Service Provider</span>
                    </a>
                </li>
            <?php endif; ?>



            <!-- User -->
            <?php if ($is_super_admin || !empty($_SESSION['permissions']['user'])): ?>
                <li class="nav-item" id="nav-user">
                    <a class="nav-link" href="#" onclick="loadSection('user');return false;">
                        <i class="fas fa-fw fa-user"></i><span>User</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- ID Verifications -->
            <?php if ($is_super_admin || !empty($_SESSION['permissions']['dealer'])): ?>
                <li class="nav-item" id="nav-verification">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('verification');return false;">
                        <div>
                            <i class="fas fa-fw fa-id-card"></i>
                            <span>ID Verifications</span>
                        </div>
                        <?php if (!empty($cnt_verifications) && $cnt_verifications > 0): ?>
                            <span class="badge badge-danger badge-counter font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em; position: static; transform: none;"><?= $cnt_verifications ?></span>
                        <?php endif; ?>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Services -->
            <?php if ($is_super_admin || !empty($_SESSION['permissions']['dealer'])): ?>
                <li class="nav-item" id="nav-service">
                    <a class="nav-link" href="#" onclick="loadSection('service');return false;">
                        <i class="fas fa-fw fa-cogs"></i><span>Services</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Manage Logo -->
            <?php if ($is_super_admin): ?>
                <li class="nav-item" id="nav-logo">
                    <a class="nav-link" href="#" onclick="loadSection('logo');return false;">
                        <i class="fas fa-fw fa-image"></i><span>Manage Logo</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Blog Management -->
            <li class="nav-item" id="nav-blogs">
                <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('blogs');return false;">
                    <div>
                        <i class="fas fa-fw fa-newspaper"></i>
                        <span>Blog Management</span>
                    </div>
                    <?php if (!empty($cnt_blogs) && $cnt_blogs > 0): ?>
                        <span class="badge badge-emerald font-weight-bold" style="background:#05c279; color:#fff; font-size: 0.65rem; padding: 0.25em 0.6em;"><?= $cnt_blogs ?></span>
                    <?php endif; ?>
                </a>
            </li>

            <!-- Categories & Subcategories Management -->
            <li class="nav-item" id="nav-categories">
                <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('categories');return false;">
                    <div>
                        <i class="fas fa-fw fa-layer-group"></i>
                        <span>Categories & Subs</span>
                    </div>
                    <?php if (!empty($cnt_categories) && $cnt_categories > 0): ?>
                        <span class="badge badge-info font-weight-bold" style="background:#36b9cc; color:#fff; font-size: 0.65rem; padding: 0.25em 0.6em;"><?= $cnt_categories ?></span>
                    <?php endif; ?>
                </a>
            </li>

            <!-- Convenience Fee (Platform Fee) Management -->
            <li class="nav-item" id="nav-convenience_fee">
                <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('convenience_fee');return false;">
                    <div>
                        <i class="fas fa-fw fa-hand-holding-usd text-warning"></i>
                        <span>Convenience Fee</span>
                    </div>
                    <span class="badge badge-pill badge-primary font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">₹ IN</span>
                </a>
            </li>

            <!-- Global OTP Login Configuration — Super Admin Only -->
            <?php if ($is_super_admin): ?>
                <li class="nav-item" id="nav-otp_config">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('otp_config');return false;">
                        <div>
                            <i class="fas fa-fw fa-shield-alt text-success"></i>
                            <span>OTP Login Settings</span>
                        </div>
                        <span class="badge badge-success font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">OTP</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Gmail SMTP Setup — Super Admin Only -->
            <?php if ($is_super_admin): ?>
                <li class="nav-item" id="nav-smtp_settings">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('smtp_settings');return false;">
                        <div>
                            <i class="fas fa-fw fa-envelope text-primary"></i>
                            <span>SMTP Setup</span>
                        </div>
                        <span class="badge badge-primary font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">SMTP</span>
                    </a>
                </li>
            <?php endif; ?>

            <!-- Payment Gateway Key Configuration — Super Admin Only -->
            <?php if ($is_super_admin): ?>
                <li class="nav-item" id="nav-payment_gateway">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('payment_gateway');return false;">
                        <div>
                            <i class="fas fa-fw fa-key text-success"></i>
                            <span>Payment Gateway</span>
                        </div>
                        <span class="badge badge-success font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">RZP</span>
                    </a>
                </li>

                <!-- Live Domain & URLs Configuration — Super Admin Only -->
                <li class="nav-item" id="nav-domain_config">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('domain_config');return false;">
                        <div>
                            <i class="fas fa-fw fa-globe text-primary"></i>
                            <span>Live Domain & URLs</span>
                        </div>
                        <span class="badge badge-primary font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">LIVE</span>
                    </a>
                </li>

                <hr class="sidebar-divider my-2">
                <div class="sidebar-heading">Account & System</div>

                <!-- Profile -->
                <li class="nav-item" id="nav-profile">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('profile');return false;">
                        <div>
                            <i class="fas fa-fw fa-user-circle text-info"></i>
                            <span>Profile</span>
                        </div>
                        <span class="badge badge-info font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">ME</span>
                    </a>
                </li>

                <!-- Settings -->
                <li class="nav-item" id="nav-settings">
                    <a class="nav-link d-flex align-items-center justify-content-between" href="#" onclick="loadSection('settings');return false;">
                        <div>
                            <i class="fas fa-fw fa-cogs text-warning"></i>
                            <span>Settings</span>
                        </div>
                        <span class="badge badge-warning font-weight-bold" style="font-size: 0.65rem; padding: 0.25em 0.6em;">SYS</span>
                    </a>
                </li>
            <?php endif; ?>

            <hr class="sidebar-divider d-none d-md-block">
            <div class="text-center d-none d-md-inline">
                <button class="rounded-circle border-0" id="sidebarToggle"></button>
            </div>
        </ul>
        <!-- ═══════════════════ END SIDEBAR ═══════════════════ -->

        <div id="content-wrapper" class="d-flex flex-column">
            <div id="content">

                <!-- ═════════════ TOPBAR ═════════════ -->
                <nav class="navbar navbar-expand navbar-light bg-white topbar mb-4 static-top shadow">
                    <button id="sidebarToggleTop" class="btn btn-link d-md-none rounded-circle mr-3">
                        <i class="fa fa-bars"></i>
                    </button>

                    <ul class="navbar-nav ml-auto">

                        <!-- Admin count — super_admin only -->
                        <?php if ($is_super_admin): ?>
                            <li class="nav-item no-arrow mx-1" title="Admins">
                                <a class="nav-link" href="#" onclick="loadSection('admin');return false;">
                                    <i class="fas fa-user-shield fa-fw"></i>
                                    <span class="badge badge-danger badge-counter"><?= $cnt_admin ?></span>
                                </a>
                            </li>
                        <?php endif; ?>

                        <li class="nav-item no-arrow mx-1" title="Service Providers">
                            <a class="nav-link" href="#" onclick="loadSection('dealer');return false;">
                                <i class="fas fa-handshake fa-fw"></i>
                                <span class="badge badge-danger badge-counter"><?= $cnt_dealer ?></span>
                            </a>
                        </li>

                        <li class="nav-item no-arrow mx-1" title="Users">
                            <a class="nav-link" href="#" onclick="loadSection('user');return false;">
                                <i class="fas fa-users fa-fw"></i>
                                <span class="badge badge-danger badge-counter"><?= $cnt_user ?></span>
                            </a>
                        </li>

                        <!-- Alerts -->
                        <li class="nav-item dropdown no-arrow mx-1">
                            <a class="nav-link dropdown-toggle" href="#" id="alertsDropdown" role="button"
                                data-toggle="dropdown">
                                <i class="fas fa-bell fa-fw"></i>
                                <span class="badge badge-danger badge-counter">3+</span>
                            </a>
                            <div class="dropdown-list dropdown-menu dropdown-menu-right shadow animated--grow-in"
                                aria-labelledby="alertsDropdown">
                                <h6 class="dropdown-header">Alerts Center</h6>
                                <a class="dropdown-item text-center small text-gray-500" href="#">Show All Alerts</a>
                            </div>
                        </li>

                        <div class="topbar-divider d-none d-sm-block"></div>

                        <!-- User dropdown -->
                        <li class="nav-item dropdown no-arrow">
                            <a class="nav-link dropdown-toggle" href="#" id="userDropdown" role="button"
                                data-toggle="dropdown">
                                <span class="mr-2 d-none d-lg-inline text-gray-600 small" id="topbar-user-name">
                                    <?= htmlspecialchars($_SESSION['admin_name'] ?? 'Admin') ?>
                                </span>
                                <img class="img-profile rounded-circle" src="img/undraw_profile.svg">
                            </a>
                            <div class="dropdown-menu dropdown-menu-right shadow animated--grow-in"
                                aria-labelledby="userDropdown">
                                <a class="dropdown-item" href="#" onclick="loadSection('profile');return false;"><i
                                        class="fas fa-user fa-sm fa-fw mr-2 text-gray-400"></i> Profile</a>
                                <a class="dropdown-item" href="#" onclick="loadSection('settings');return false;"><i
                                        class="fas fa-cogs fa-sm fa-fw mr-2 text-gray-400"></i> Settings</a>
                                <div class="dropdown-divider"></div>
                                <a class="dropdown-item" href="#" data-toggle="modal" data-target="#logoutModal">
                                    <i class="fas fa-sign-out-alt fa-sm fa-fw mr-2 text-gray-400"></i> Logout
                                </a>
                            </div>
                        </li>
                    </ul>
                </nav>
                <!-- ═════════════ END TOPBAR ═════════════ -->

                <!-- ═════════════ MAIN CONTENT ═════════════ -->
                <div class="container-fluid">

                    <!-- ── DASHBOARD HOME (default view) ─────────────────────── -->
                    <div id="dashboard-home">
                        <div class="d-sm-flex align-items-center justify-content-between mb-4">
                            <h1 class="h3 mb-0 text-gray-800">Dashboard</h1>
                        </div>

                        <!-- KPI Cards -->
                        <div class="row">

                            <!-- Admin card — super_admin only -->
                            <?php if ($is_super_admin): ?>
                                <div class="col-xl-3 col-md-6 mb-4">
                                    <div class="card border-left-primary shadow h-100 py-2" style="cursor:pointer"
                                        onclick="loadSection('admin')">
                                        <div class="card-body">
                                            <div class="row no-gutters align-items-center">
                                                <div class="col mr-2">
                                                    <div class="text-xs font-weight-bold text-primary text-uppercase mb-1">
                                                        Total Admins</div>
                                                    <div class="h5 mb-0 font-weight-bold text-gray-800"><?= $cnt_admin ?>
                                                    </div>
                                                </div>
                                                <div class="col-auto"><i class="fas fa-user-shield fa-2x text-gray-300"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if ($is_super_admin || !empty($_SESSION['permissions']['dealer'])): ?>
                                <div class="col-xl-3 col-md-6 mb-4">
                                    <div class="card border-left-success shadow h-100 py-2" style="cursor:pointer"
                                        onclick="loadSection('dealer')">
                                        <div class="card-body">
                                            <div class="row no-gutters align-items-center">
                                                <div class="col mr-2">
                                                    <div class="text-xs font-weight-bold text-success text-uppercase mb-1">
                                                        Total Service Providers</div>
                                                    <div class="h5 mb-0 font-weight-bold text-gray-800"><?= $cnt_dealer ?>
                                                    </div>
                                                </div>
                                                <div class="col-auto"><i class="fas fa-handshake fa-2x text-gray-300"></i>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endif; ?>



                            <?php if ($is_super_admin || !empty($_SESSION['permissions']['user'])): ?>
                                <div class="col-xl-3 col-md-6 mb-4">
                                    <div class="card border-left-warning shadow h-100 py-2" style="cursor:pointer"
                                        onclick="loadSection('user')">
                                        <div class="card-body">
                                            <div class="row no-gutters align-items-center">
                                                <div class="col mr-2">
                                                    <div class="text-xs font-weight-bold text-warning text-uppercase mb-1">
                                                        Total Users</div>
                                                    <div class="h5 mb-0 font-weight-bold text-gray-800"><?= $cnt_user ?>
                                                    </div>
                                                </div>
                                                <div class="col-auto"><i class="fas fa-users fa-2x text-gray-300"></i></div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <!-- Categories & Subcategories KPI -->
                            <div class="col-xl-3 col-md-6 mb-4">
                                <div class="card border-left-info shadow h-100 py-2" style="cursor:pointer"
                                    onclick="loadSection('categories')">
                                    <div class="card-body">
                                        <div class="row no-gutters align-items-center">
                                            <div class="col mr-2">
                                                <div class="text-xs font-weight-bold text-info text-uppercase mb-1">
                                                    Categories</div>
                                                <div class="h5 mb-0 font-weight-bold text-gray-800"><?= $cnt_categories ?>
                                                </div>
                                            </div>
                                            <div class="col-auto"><i class="fas fa-layer-group fa-2x text-gray-300"></i></div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div><!-- /.row KPI -->

                        <!-- Charts -->
                        <div class="row">
                            <div class="col-xl-8 col-lg-7">
                                <div class="card shadow mb-4">
                                    <div
                                        class="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                                        <h6 class="m-0 font-weight-bold text-emerald">Earnings Overview</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="chart-area"><canvas id="myAreaChart"></canvas></div>
                                    </div>
                                </div>
                            </div>
                            <div class="col-xl-4 col-lg-5">
                                <div class="card shadow mb-4">
                                    <div
                                        class="card-header py-3 d-flex flex-row align-items-center justify-content-between">
                                        <h6 class="m-0 font-weight-bold text-emerald">Revenue Sources</h6>
                                    </div>
                                    <div class="card-body">
                                        <div class="chart-pie pt-4 pb-2"><canvas id="myPieChart"></canvas></div>
                                        <div class="mt-4 text-center small">
                                            <span class="mr-2"><i class="fas fa-circle text-emerald"></i> Direct</span>
                                            <span class="mr-2"><i class="fas fa-circle text-success"></i> Social</span>
                                            <span class="mr-2"><i class="fas fa-circle text-info"></i> Referral</span>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div><!-- /#dashboard-home -->

                    <!-- ── AJAX LIST PANEL ─────────────────────────────────── -->
                    <div id="list-panel" style="display:none;">
                        <div id="list-spinner">
                            <div class="spinner-border" role="status"></div>
                            <p class="mt-3 text-muted small">Loading data...</p>
                        </div>
                        <div id="list-content"></div>
                    </div>

                </div><!-- /.container-fluid -->
            </div><!-- /#content -->

            <!-- Footer -->
            <footer class="sticky-footer bg-white">
                <div class="container my-auto">
                    <div class="copyright text-center my-auto">
                        <span>Copyright &copy; ServEasy <?= date('Y') ?></span>
                    </div>
                </div>
            </footer>
        </div><!-- /#content-wrapper -->
    </div><!-- /#wrapper -->

    <!-- Scroll to top -->
    <a class="scroll-to-top rounded" href="#page-top"><i class="fas fa-angle-up"></i></a>

    <!-- Logout Modal -->
    <div class="modal fade" id="logoutModal" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title">Ready to Leave?</h5>
                    <button class="close" type="button" data-dismiss="modal"><span>×</span></button>
                </div>
                <div class="modal-body">Select "Logout" below if you are ready to end your current session.</div>
                <div class="modal-footer">
                    <button class="btn btn-secondary" type="button" data-dismiss="modal">Cancel</button>
                    <a class="btn btn-emerald" href="logout.php">Logout</a>
                </div>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="vendor/jquery/jquery.min.js"></script>
    <script src="vendor/bootstrap/js/bootstrap.bundle.min.js"></script>
    <script src="vendor/jquery-easing/jquery.easing.min.js"></script>
    <script src="js/sb-admin-2.min.js"></script>
    <script src="js/notify.js"></script>
    <script src="vendor/chart.js/Chart.min.js"></script>
    <script src="js/demo/chart-area-demo.js"></script>
    <script src="js/demo/chart-pie-demo.js"></script>

    <script>
        $(document).ready(function() {
            $('#content-wrapper').on('scroll', function() {
                if ($(this).scrollTop() > 100) {
                    $('.scroll-to-top').fadeIn();
                } else {
                    $('.scroll-to-top').fadeOut();
                }
            });
            $(document).on('click', 'a.scroll-to-top', function(e) {
                e.preventDefault();
                $('#content-wrapper').stop().animate({ scrollTop: 0 }, 500, 'easeInOutExpo');
            });
        });

        var currentSection = '';
        var isSuperAdmin = <?= $is_super_admin ? 'true' : 'false' ?>;
        var validTabs = <?= json_encode($is_super_admin ? ['admin', 'dealer', 'user', 'verification', 'logo', 'service', 'blogs', 'categories', 'dealer_services', 'convenience_fee', 'payment_gateway', 'otp_config', 'smtp_settings', 'domain_config', 'profile', 'settings'] : ['dealer', 'user', 'verification', 'service', 'blogs', 'categories', 'dealer_services', 'convenience_fee', 'profile']) ?>;

        // Show dashboard home
        function showDashboard() {
            currentSection = '';
            $('#dashboard-home').show();
            $('#list-panel').hide();
            $('#list-content').html('');
            setActiveNav('home');
            sessionStorage.removeItem('serveasy_superadmin_tab');
            sessionStorage.removeItem('serveasy_superadmin_id');
            history.pushState({}, '', window.location.pathname);
            document.title = 'Dashboard – ServEasy';
        }

        const sectionCache = {};

        // Load a list via AJAX (Cache-First with instant 0ms switching)
        function loadSection(type) {
            // Guard: block super admin sections for non-super-admins
            if ((type === 'admin' || type === 'payment_gateway' || type === 'otp_config' || type === 'smtp_settings' || type === 'domain_config' || type === 'settings') && !isSuperAdmin) return;

            if (currentSection === type) return; // already shown
            currentSection = type;

            $('#dashboard-home').hide();
            $('#list-panel').show();
            setActiveNav(type);
            sessionStorage.setItem('serveasy_superadmin_tab', type);
            sessionStorage.removeItem('serveasy_superadmin_id');
            history.pushState({ tab: type }, '', window.location.pathname + '?tab=' + type);

            // Instant render from client memory cache if previously viewed
            if (sectionCache[type]) {
                $('#list-content').html(sectionCache[type]);
                $('#list-spinner').hide();
                document.title = capitalize(type) + 's – ServEasy';
            } else {
                $('#list-content').html('');
                $('#list-spinner').show();
            }

            $.ajax({
                url: 'superadmin-dashboard.php',
                type: 'GET',
                data: { ajax_action: 'fetch_list', type: type },
                success: function (html) {
                    $('#list-spinner').hide();
                    sectionCache[type] = html;
                    $('#list-content').html(html);
                    document.title = capitalize(type) + 's – ServEasy';
                },
                error: function () {
                    $('#list-spinner').hide();
                    if (!sectionCache[type]) {
                        $('#list-content').html('<div class="alert alert-danger mt-3">Failed to load data. Please try again.</div>');
                    }
                }
            });
        }

        // Submit toggle/permission form via AJAX then reload the list
        function submitToggleForm(checkbox) {
            var form = $(checkbox).closest('form');
            $.post('superadmin-dashboard.php?ajax_action=fetch_list', form.serialize(), function (res) {
                if (res && res.ok) {
                    var section = currentSection;
                    delete sectionCache[section];
                    currentSection = '';  // force reload
                    loadSection(section);
                } else {
                    checkbox.checked = !checkbox.checked;
                    alert('Could not update status.');
                }
            }, 'json').fail(function () {
                checkbox.checked = !checkbox.checked;
                alert('Server error updating status.');
            });
        }
        function submitPermForm(checkbox) { submitToggleForm(checkbox); }

        
        function scrollToProviderServices() {
            var el = document.getElementById('provider-services-section');
            if (el) {
                el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                el.style.transition = 'background-color 0.5s ease';
                var origBg = el.style.backgroundColor;
                el.style.backgroundColor = 'rgba(28, 200, 138, 0.15)';
                el.style.borderRadius = '8px';
                setTimeout(function() { el.style.backgroundColor = origBg; }, 1800);
            } else {
                if (typeof Notify !== 'undefined') Notify.info('Viewing provider services.');
            }
        }

        async function submitDealerVerification(btn, dealerId, statusVal) {
            var reason = '';
            if (statusVal === 'rejected') {
                if (typeof Notify !== 'undefined' && Notify.prompt) {
                    var resReason = await Notify.prompt('Please enter the rejection reason for this service provider (optional):', {
                        title: 'Reject Service Provider',
                        placeholder: 'Reason for rejection...',
                        confirmText: 'Reject Provider',
                        cancelText: 'Cancel',
                        type: 'danger'
                    });
                    if (resReason === null) return;
                    reason = resReason;
                } else {
                    reason = prompt('Please enter rejection reason (optional):');
                    if (reason === null) return;
                }
            }
            var postData = {
                toggle_dealer_verification_id: dealerId,
                new_verification_status: statusVal,
                rejection_reason: reason
            };
            $(btn).prop('disabled', true).html('<i class="fas fa-spinner fa-spin"></i>');
            $.post('superadmin-dashboard.php?ajax_action=fetch_list', postData, function (res) {
                if (res && res.ok) {
                    if (typeof Notify !== 'undefined') Notify.success(res.message || 'Provider status updated.');
                    var section = currentSection;
                    currentSection = '';
                    loadSection(section || 'dealer');
                } else {
                    if (typeof Notify !== 'undefined') Notify.error((res && res.message) ? res.message : 'Error updating status.');
                    $(btn).prop('disabled', false).text(statusVal === 'approved' ? 'Approve' : 'Reject');
                }
            }, 'json').fail(function () {
                if (typeof Notify !== 'undefined') Notify.error('Server error.');
                $(btn).prop('disabled', false).text(statusVal === 'approved' ? 'Approve' : 'Reject');
            });
        }

        async function submitDetailDealerVerification(dealerId, statusVal) {
            var reason = '';
            if (statusVal === 'rejected') {
                if (typeof Notify !== 'undefined' && Notify.prompt) {
                    var resReason = await Notify.prompt('Please enter the rejection reason for this service provider (optional):', {
                        title: 'Reject Service Provider',
                        placeholder: 'Reason for rejection...',
                        confirmText: 'Reject Provider',
                        cancelText: 'Cancel',
                        type: 'danger'
                    });
                    if (resReason === null) return;
                    reason = resReason;
                } else {
                    reason = prompt('Please enter rejection reason (optional):');
                    if (reason === null) return;
                }
            }
            var postData = {
                ajax_action: 'fetch_detail',
                type: 'dealer',
                toggle_dealer_verification_id: dealerId,
                new_verification_status: statusVal,
                rejection_reason: reason
            };
            $.post('superadmin-dashboard.php', postData, function (res) {
                if (res && res.ok) {
                    if (typeof Notify !== 'undefined') Notify.success(res.message || 'Provider status updated.');
                    loadDetail('dealer', dealerId);
                } else {
                    if (typeof Notify !== 'undefined') Notify.error((res && res.message) ? res.message : 'Error updating status.');
                }
            }, 'json').fail(function () {
                if (typeof Notify !== 'undefined') Notify.error('Server error.');
            });
        }

        // Highlight active sidebar item
        function setActiveNav(section) {
            $('.nav-item').removeClass('active-section');
            $('#nav-' + section).addClass('active-section');
        }

        // Browser back/forward
        window.addEventListener('popstate', function (e) {
            var params = new URLSearchParams(window.location.search);
            var tab = params.get('tab') || params.get('type') || (e.state && e.state.tab);
            var rawId = params.get('id') || (e.state && e.state.id);
            var id = parseInt(rawId, 10);
            if (isNaN(id) || id <= 0) id = null;

            if (tab === 'dealer_services' && id) {
                currentSection = '';
                loadProviderServices(id);
            } else if (tab && validTabs.indexOf(tab) !== -1) {
                currentSection = '';
                if (id) {
                    loadDetail(tab, id);
                } else {
                    loadSection(tab);
                }
            } else {
                showDashboard();
            }
        });

        function capitalize(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

        // Init
        $(document).ready(function () {
            var params = new URLSearchParams(window.location.search);
            var tab = params.get('tab') || params.get('type') || '<?= $open_tab ?>';
            var rawId = params.get('id') || '<?= $open_id ? $open_id : "" ?>';
            var id = parseInt(rawId, 10);
            if (isNaN(id) || id <= 0) id = null;

            // Clean up any stale query parameters or invalid id=0 from earlier browser redirects
            if (params.get('action') === 'save_edit' || params.get('permission_admin_id') || (params.has('id') && !id)) {
                var cleanUrl = window.location.pathname + (tab ? '?tab=' + tab : '') + (id ? '&id=' + id : '');
                history.replaceState({ tab: tab, id: id }, '', cleanUrl);
            }

            // Fallback to sessionStorage if URL had no parameters
            if (!tab) {
                var savedTab = sessionStorage.getItem('serveasy_superadmin_tab');
                var rawSavedId = sessionStorage.getItem('serveasy_superadmin_id');
                var savedId = parseInt(rawSavedId, 10);
                if (isNaN(savedId) || savedId <= 0) savedId = null;
                if (savedTab && validTabs.indexOf(savedTab) !== -1) {
                    tab = savedTab;
                    id = savedId;
                    var newUrl = window.location.pathname + '?tab=' + tab + (id ? '&id=' + id : '');
                    history.replaceState({ tab: tab, id: id }, '', newUrl);
                }
            }

            if (tab === 'dealer_services' && id) {
                loadProviderServices(id);
            } else if (tab && validTabs.indexOf(tab) !== -1) {
                if (id) {
                    loadDetail(tab, id);
                } else {
                    loadSection(tab);
                }
            } else {
                setActiveNav('home');
            }
        });

        // ── Load admin detail view inline (no page redirect) ─────
        function loadDetail(type, id) {
            var intId = parseInt(id, 10);
            if (isNaN(intId) || intId <= 0) {
                console.warn('loadDetail called with invalid id (' + id + '). Redirecting to loadSection.');
                loadSection(type);
                return;
            }
            id = intId;
            currentSection = type + '_detail';
            $('#list-content').html('');
            $('#list-spinner').show();
            $('#list-panel').show();
            $('#dashboard-home').hide();
            setActiveNav(type);
            sessionStorage.setItem('serveasy_superadmin_tab', type);
            sessionStorage.setItem('serveasy_superadmin_id', id);
            history.pushState({ tab: type, id: id }, '', window.location.pathname + '?tab=' + type + '&id=' + id);
            document.title = capitalize(type) + ' Details – ServEasy';

            $.ajax({
                url: 'superadmin-dashboard.php',
                type: 'GET',
                data: { ajax_action: 'fetch_detail', type: type, id: id },
                success: function (html) {
                    $('#list-spinner').hide();
                    $('#list-content').html(html);
                },
                error: function () {
                    $('#list-spinner').hide();
                    $('#list-content').html('<div class="alert alert-danger mt-3">Failed to load admin details.</div>');
                }
            });
        }

        // Toggle status from within the detail view then reload detail
        function submitDetailToggle(btn, type) {
            var form = $(btn).closest('form');
            $.post('superadmin-dashboard.php', form.serialize() + '&ajax_action=fetch_detail', function (res) {
                if (res && res.ok) {
                    var params = new URLSearchParams(window.location.search);
                    var id = params.get('id');
                    if (id) {
                        currentSection = '';
                        loadDetail(type || 'admin', id);
                    }
                } else {
                    alert('Could not update status.');
                }
            }, 'json').fail(function () {
                alert('Server error updating status.');
            });
        }

        // Dedicated AJAX toggle for module permissions (No full page reload!)
        function submitPermToggle(checkbox, adminId, permType) {
            var isChecked = checkbox.checked;
            var permVal = isChecked ? 1 : 0;
            var card = $(checkbox).closest('.card');
            var icon = card.find('i');

            $(checkbox).prop('disabled', true);

            $.ajax({
                url: 'superadmin-dashboard.php',
                type: 'POST',
                data: {
                    ajax_action: 'fetch_detail',
                    type: 'admin',
                    permission_admin_id: adminId,
                    perm_type: permType,
                    perm_val: permVal
                },
                dataType: 'json',
                success: function (res) {
                    $(checkbox).prop('disabled', false);
                    if (res && res.ok) {
                        if (isChecked) {
                            icon.css('color', '#05c279');
                        } else {
                            icon.css('color', '#ccc');
                        }
                    } else {
                        checkbox.checked = !isChecked;
                        alert('Could not update permission: ' + (res && res.message ? res.message : 'Error'));
                    }
                },
                error: function (xhr, status, error) {
                    $(checkbox).prop('disabled', false);
                    checkbox.checked = !isChecked;
                    console.error('Permission AJAX error:', xhr.responseText);
                    alert('Server error while updating permission. Please try again.');
                }
            });
        }

        function submitPermFormDetail(checkbox, adminId, type) {
            var form = $(checkbox).closest('form');
            var permType = form.find('input[name="perm_type"]').val() || 'dealer';
            submitPermToggle(checkbox, adminId, permType);
        }

        function toggleEditMode(type, id, editMode) {
            currentSection = ''; // reset to allow reload
            $('#list-content').html('');
            $('#list-spinner').show();
            
            $.ajax({
                url: 'superadmin-dashboard.php',
                type: 'GET',
                data: { ajax_action: 'fetch_detail', type: type, id: id, edit_mode: editMode ? '1' : '0' },
                success: function (html) {
                    $('#list-spinner').hide();
                    $('#list-content').html(html);
                },
                error: function () {
                    $('#list-spinner').hide();
                    $('#list-content').html('<div class="alert alert-danger mt-3">Failed to load edit view.</div>');
                }
            });
        }

        function saveEdit(type, id) {
            var form = $('#editForm');
            $.post('superadmin-dashboard.php?ajax_action=fetch_detail&type=' + type, form.serialize(), function (res) {
                if (res && res.ok) {
                    loadDetail(type, id);
                } else {
                    Notify.error('Failed to save changes.');
                }
            }, 'json').fail(function() {
                Notify.error('An error occurred while saving.');
            });
        }

        async function deleteRecord(type, id) {
            const confirmed = await Notify.confirm('Are you sure you want to permanently delete this ' + type + '? This action cannot be undone.', { type: 'danger', title: 'Confirm Delete' });
            if (!confirmed) return;
            
            $.post('superadmin-dashboard.php?ajax_action=fetch_detail&type=' + type, { action: 'delete_record', id: id }, function (res) {
                if (res && res.ok) {
                    loadSection(type);
                } else {
                    Notify.error('Failed to delete record.');
                }
            }, 'json').fail(function() {
                Notify.error('An error occurred while deleting.');
            });
        }

        // ── Provider Services Container View Handler (Same Tab) ───────
        function loadProviderServices(providerId) {
            if (!providerId) return;
            currentSection = 'dealer_services_' + providerId;
            $('#dashboard-home').hide();
            $('#list-content').html('');
            $('#list-spinner').show();
            $('#list-panel').show();
            setActiveNav('dealer');

            sessionStorage.setItem('serveasy_superadmin_tab', 'dealer_services');
            sessionStorage.setItem('serveasy_superadmin_id', providerId);
            history.pushState({ tab: 'dealer_services', id: providerId }, '', window.location.pathname + '?tab=dealer_services&id=' + providerId);

            $.get('superadmin-dashboard.php', { ajax_action: 'fetch_provider_services_view', provider_id: providerId }, function (html) {
                $('#list-spinner').hide();
                $('#list-content').html(html);
                document.title = 'Provider Services – ServEasy';
            }).fail(function () {
                $('#list-spinner').hide();
                $('#list-content').html('<div class="alert alert-danger m-4">Failed to load provider services. Please try again.</div>');
            });
        }

        async function submitProviderServiceAction(srvId, newStatus, providerId) {
            if (newStatus === 'rejected') {
                var reason = '';
                if (typeof Notify !== 'undefined' && Notify.prompt) {
                    var resReason = await Notify.prompt('Please enter the rejection reason for this service (optional):', {
                        title: 'Reject Service',
                        placeholder: 'Reason for rejection...',
                        confirmText: 'Reject Service',
                        cancelText: 'Cancel',
                        type: 'danger'
                    });
                    if (resReason === null) return;
                    reason = resReason;
                } else {
                    reason = prompt('Please enter rejection reason (optional):');
                    if (reason === null) return;
                }
            }

            var postData = {
                ajax_action: 'fetch_provider_services_view',
                toggle_service_id: srvId,
                new_service_status: newStatus,
                rejection_reason: reason || ''
            };

            $.post('superadmin-dashboard.php', postData, function (res) {
                if (res && res.ok) {
                    if (typeof Notify !== 'undefined') {
                        Notify.success(res.message || 'Service status updated successfully.');
                    }
                    // Refresh container view
                    $.get('superadmin-dashboard.php', { ajax_action: 'fetch_provider_services_view', provider_id: providerId }, function (html) {
                        $('#list-content').html(html);
                    });
                } else {
                    if (typeof Notify !== 'undefined') {
                        Notify.error((res && res.message) ? res.message : 'Error updating service status.');
                    } else {
                        alert((res && res.message) ? res.message : 'Error updating service status.');
                    }
                }
            }, 'json').fail(function () {
                if (typeof Notify !== 'undefined') {
                    Notify.error('Server error updating service status.');
                } else {
                    alert('Server error updating service status.');
                }
            });
        }
    

        // ================= DOCUMENT ZOOM LIGHTBOX LOGIC =================
        var currentDocScale = 1.0;
        var currentDocRotate = 0;
        var currentPanX = 0;
        var currentPanY = 0;
        var isDocPanning = false;
        var panStartX = 0;
        var panStartY = 0;
        var currentDocUrl = '';
        var currentDocTitle = '';

        function updateDocZoomTransform() {
            var wrapper = document.getElementById('docZoomContentWrapper');
            var badge = document.getElementById('docZoomScaleBadge');
            if (!wrapper) return;
            wrapper.style.transform = 'translate(' + currentPanX + 'px, ' + currentPanY + 'px) scale(' + currentDocScale + ') rotate(' + currentDocRotate + 'deg)';
            if (badge) {
                badge.textContent = Math.round(currentDocScale * 100) + '%';
            }
        }

        window.triggerDirectDownload = function(overrideUrl, overrideTitle) {
            var url = overrideUrl || currentDocUrl;
            if (!url) return;
            var title = overrideTitle || currentDocTitle || 'document';
            var btn = document.getElementById('docZoomDownloadBtn');
            var originalHtml = btn ? btn.innerHTML : '';
            if (btn) {
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i><span class="d-none d-md-inline ml-1">Saving...</span>';
                btn.disabled = true;
            }

            var cleanTitle = title.replace(/[^a-zA-Z0-9_-]/g, '_');
            var ext = url.split('.').pop().split('?')[0].toLowerCase();
            if (!['jpg', 'jpeg', 'png', 'webp', 'avif', 'pdf'].includes(ext)) {
                ext = 'jpg';
            }
            if (ext === 'jpeg') ext = 'jpg';
            var downloadFileName = cleanTitle + '.' + ext;

            function restoreBtn() {
                if (btn) {
                    btn.innerHTML = originalHtml;
                    btn.disabled = false;
                }
            }

            // Route through ScalePixel Content-Disposition download endpoint when applicable
            var directDownloadUrl = url;
            if (url.includes('scalepixel.onrender.com/storage/temp/')) {
                var fileName = url.split('/storage/temp/').pop().split('?')[0];
                directDownloadUrl = 'https://scalepixel.onrender.com/api/v1/download.php?file=' + encodeURIComponent(fileName);
            } else if (url.includes('scalepixel.onrender.com/uploads/')) {
                var fileName = url.split('/uploads/').pop().split('?')[0];
                directDownloadUrl = 'https://scalepixel.onrender.com/api/v1/download.php?file=' + encodeURIComponent(fileName);
            }

            // Strategy 1: Fetch as Blob with custom filename
            fetch(directDownloadUrl)
                .then(function(res) {
                    if (!res.ok) throw new Error('Fetch failed with status ' + res.status);
                    return res.blob();
                })
                .then(function(blob) {
                    var blobUrl = window.URL.createObjectURL(blob);
                    var link = document.createElement('a');
                    link.style.display = 'none';
                    link.href = blobUrl;
                    link.download = downloadFileName;
                    document.body.appendChild(link);
                    link.click();
                    setTimeout(function() {
                        window.URL.revokeObjectURL(blobUrl);
                        document.body.removeChild(link);
                        restoreBtn();
                    }, 500);
                })
                .catch(function(err) {
                    console.warn('[DocZoom] Direct blob fetch error, falling back to direct anchor download:', err);
                    // Strategy 2: Direct browser download trigger via anchor
                    var fallbackLink = document.createElement('a');
                    fallbackLink.style.display = 'none';
                    fallbackLink.href = directDownloadUrl;
                    fallbackLink.setAttribute('download', downloadFileName);
                    fallbackLink.target = '_blank';
                    document.body.appendChild(fallbackLink);
                    fallbackLink.click();
                    setTimeout(function() {
                        document.body.removeChild(fallbackLink);
                        restoreBtn();
                    }, 1500);
                });
        };

        window.openDocZoomModal = function(url, title, type) {
            if (!url) return;
            type = type || 'image';
            currentDocUrl = url;
            currentDocTitle = title || 'document';

            var modal = document.getElementById('serveasyDocZoomModal');
            if (!modal) {
                var modalHtml = '<div id="serveasyDocZoomModal" class="doc-zoom-modal" tabindex="-1" role="dialog" aria-hidden="true">' +
                    '<div class="doc-zoom-backdrop" onclick="closeDocZoomModal()"></div>' +
                    '<div class="doc-zoom-container">' +
                        '<div class="doc-zoom-header">' +
                            '<div class="doc-zoom-title-area d-flex align-items-center">' +
                                '<span class="mr-2"><i class="fas fa-shield-alt text-emerald"></i></span>' +
                                '<span id="docZoomTitle" class="doc-zoom-title font-weight-bold text-white">Document Preview</span>' +
                                '<span id="docZoomScaleBadge" class="badge badge-dark ml-3 px-2 py-1" style="font-size:0.75rem;background:rgba(255,255,255,0.15);">100%</span>' +
                                '<span id="docZoomResBadge" class="badge badge-info ml-2 px-2 py-1" style="font-size:0.75rem;background:rgba(14,165,233,0.25);border:1px solid rgba(14,165,233,0.4);color:#38bdf8;display:none;"></span>' +
                            '</div>' +
                            '<div class="doc-zoom-actions d-flex align-items-center" style="gap:8px;">' +
                                '<button type="button" class="btn btn-sm btn-zoom-action" title="100% Native Pixel Size (1:1)" onclick="docZoomAction(\'1to1\')"><i class="fas fa-expand-arrows-alt"></i><span class="d-none d-md-inline ml-1">1:1 Size</span></button>' +
                                '<button type="button" class="btn btn-sm btn-zoom-action" title="Zoom In" onclick="docZoomAction(\'in\')"><i class="fas fa-search-plus"></i><span class="d-none d-md-inline ml-1">Zoom In</span></button>' +
                                '<button type="button" class="btn btn-sm btn-zoom-action" title="Zoom Out" onclick="docZoomAction(\'out\')"><i class="fas fa-search-minus"></i><span class="d-none d-md-inline ml-1">Zoom Out</span></button>' +
                                '<button type="button" class="btn btn-sm btn-zoom-action" title="Rotate 90°" onclick="docZoomAction(\'rotate\')"><i class="fas fa-redo"></i><span class="d-none d-md-inline ml-1">Rotate</span></button>' +
                                '<button type="button" class="btn btn-sm btn-zoom-action" title="Fit to Screen" onclick="docZoomAction(\'reset\')"><i class="fas fa-sync-alt"></i><span class="d-none d-md-inline ml-1">Fit</span></button>' +
                                '<button type="button" id="docZoomDownloadBtn" class="btn btn-sm btn-zoom-action btn-zoom-download" title="Download Image Directly" onclick="triggerDirectDownload()"><i class="fas fa-download"></i><span class="d-none d-md-inline ml-1">Download</span></button>' +
                                '<button type="button" class="btn btn-sm btn-zoom-close" title="Close" onclick="closeDocZoomModal()"><i class="fas fa-times fa-lg"></i></button>' +
                            '</div>' +
                        '</div>' +
                        '<div id="docZoomStage" class="doc-zoom-stage">' +
                            '<div id="docZoomContentWrapper" class="doc-zoom-content-wrapper">' +
                                '<img id="docZoomImage" src="" alt="Document Zoomed" style="display:none;width:auto !important;height:auto !important;max-width:90vw;max-height:80vh;object-fit:contain !important;aspect-ratio:auto !important;" draggable="false" />' +
                                '<iframe id="docZoomPdfIframe" src="" style="display:none;width:90vw;height:80vh;border:none;border-radius:8px;background:#fff;"></iframe>' +
                            '</div>' +
                        '</div>' +
                        '<div class="doc-zoom-footer">' +
                            '<span><i class="fas fa-mouse mr-1"></i> Scroll to Zoom</span><span class="mx-2">•</span>' +
                            '<span><i class="fas fa-hand-paper mr-1"></i> Drag to Pan</span><span class="mx-2">•</span>' +
                            '<span>Double-Click to Toggle 2x</span><span class="mx-2">•</span>' +
                            '<span>Press <kbd style="background:rgba(255,255,255,0.2);color:#fff;padding:1px 5px;border-radius:3px;">ESC</kbd> to Close</span>' +
                        '</div>' +
                    '</div>' +
                '</div>';
                document.body.insertAdjacentHTML('beforeend', modalHtml);
                modal = document.getElementById('serveasyDocZoomModal');
                attachDocZoomListeners();
            }

            var titleEl = document.getElementById('docZoomTitle');
            var imgEl = document.getElementById('docZoomImage');
            var iframeEl = document.getElementById('docZoomPdfIframe');
            var resBadge = document.getElementById('docZoomResBadge');

            if (titleEl) titleEl.textContent = title || 'Document Preview';
            if (resBadge) {
                resBadge.style.display = 'none';
                resBadge.textContent = '';
            }

            // Reset transforms
            currentDocScale = 1.0;
            currentDocRotate = 0;
            currentPanX = 0;
            currentPanY = 0;
            updateDocZoomTransform();

            if (type === 'pdf') {
                if (imgEl) imgEl.style.display = 'none';
                if (iframeEl) {
                    iframeEl.src = url;
                    iframeEl.style.display = 'block';
                }
            } else {
                if (iframeEl) {
                    iframeEl.style.display = 'none';
                    iframeEl.src = '';
                }
                if (imgEl) {
                    imgEl.crossOrigin = 'anonymous';
                    imgEl.onload = function() {
                        var nw = imgEl.naturalWidth;
                        var nh = imgEl.naturalHeight;
                        if (nw && nh && resBadge) {
                            var r = nw / nh;
                            var ratioLabel = '';
                            if (Math.abs(r - 0.5) < 0.05) ratioLabel = '1:2 Ratio';
                            else if (Math.abs(r - 0.45) < 0.05) ratioLabel = '9:20 Ratio';
                            else if (Math.abs(r - 0.5625) < 0.05) ratioLabel = '9:16 Ratio';
                            else if (Math.abs(r - 0.75) < 0.05) ratioLabel = '3:4 Ratio';
                            else if (Math.abs(r - 1.0) < 0.05) ratioLabel = '1:1 Square';
                            else if (Math.abs(r - 1.333) < 0.05) ratioLabel = '4:3 Ratio';
                            else if (Math.abs(r - 1.777) < 0.05) ratioLabel = '16:9 Ratio';
                            else ratioLabel = (r >= 1 ? r.toFixed(1) + ':1' : '1:' + (1/r).toFixed(1)) + ' Ratio';

                            resBadge.textContent = nw + ' × ' + nh + ' px (' + ratioLabel + ')';
                            resBadge.style.display = 'inline-block';
                        }
                    };
                    imgEl.onerror = function() {
                        if (!imgEl.dataset.retried) {
                            imgEl.dataset.retried = '1';
                            setTimeout(function() {
                                imgEl.src = url + (url.indexOf('?') === -1 ? '?' : '&') + 'retry=' + Date.now();
                            }, 1500);
                        } else {
                            console.warn('[DocZoom] Could not load image from URL:', url);
                        }
                    };
                    imgEl.src = url;
                    imgEl.style.display = 'block';
                }
            }

            modal.style.cssText = 'position:fixed !important; top:0 !important; left:0 !important; width:100vw !important; height:100vh !important; z-index:99999999 !important; display:flex !important; opacity:1 !important; visibility:visible !important; flex-direction:column; align-items:center; justify-content:center;';
            modal.classList.add('active');
            document.body.style.overflow = 'hidden';
        };

        window.closeDocZoomModal = function() {
            var modal = document.getElementById('serveasyDocZoomModal');
            if (!modal) return;
            modal.classList.remove('active');
            modal.style.display = 'none';
            modal.style.opacity = '0';
            modal.style.visibility = 'hidden';
            var imgEl = document.getElementById('docZoomImage');
            var iframeEl = document.getElementById('docZoomPdfIframe');
            var resBadge = document.getElementById('docZoomResBadge');
            if (resBadge) {
                resBadge.style.display = 'none';
                resBadge.textContent = '';
            }
            if (imgEl) imgEl.src = '';
            if (iframeEl) iframeEl.src = '';
            document.body.style.overflow = '';
        };

        window.docZoomAction = function(action) {
            if (action === 'in') {
                currentDocScale = Math.min(5.0, currentDocScale + 0.25);
            } else if (action === 'out') {
                currentDocScale = Math.max(0.5, currentDocScale - 0.25);
            } else if (action === 'rotate') {
                currentDocRotate = (currentDocRotate + 90) % 360;
            } else if (action === 'reset') {
                currentDocScale = 1.0;
                currentDocRotate = 0;
                currentPanX = 0;
                currentPanY = 0;
            } else if (action === '1to1') {
                var docImg = document.getElementById('docZoomImage');
                if (docImg && docImg.naturalWidth) {
                    var displayedWidth = docImg.clientWidth || docImg.offsetWidth;
                    if (displayedWidth > 0) {
                        currentDocScale = docImg.naturalWidth / displayedWidth;
                    } else {
                        currentDocScale = 1.0;
                    }
                    currentPanX = 0;
                    currentPanY = 0;
                    currentDocRotate = 0;
                }
            }
            updateDocZoomTransform();
        };

        function attachDocZoomListeners() {
            var stage = document.getElementById('docZoomStage');
            if (!stage || stage._hasZoomListeners) return;
            stage._hasZoomListeners = true;

            // Mouse wheel to zoom
            stage.addEventListener('wheel', function(e) {
                e.preventDefault();
                if (e.deltaY < 0) {
                    docZoomAction('in');
                } else {
                    docZoomAction('out');
                }
            }, { passive: false });

            // Double click to toggle 2x zoom
            stage.addEventListener('dblclick', function(e) {
                if (e.target.tagName === 'BUTTON' || e.target.closest('button')) return;
                if (currentDocScale === 1.0) {
                    currentDocScale = 2.0;
                } else {
                    currentDocScale = 1.0;
                    currentPanX = 0;
                    currentPanY = 0;
                }
                updateDocZoomTransform();
            });

            // Single click on zoomed image toggles cursor between zoom-in and grab
            var docImg = document.getElementById('docZoomImage');
            if (docImg) {
                docImg.addEventListener('click', function(e) {
                    if (isDocPanning) return;
                    if (currentDocScale === 1.0) {
                        currentDocScale = 1.8;
                    } else if (currentDocScale < 3.0) {
                        currentDocScale = 3.0;
                    } else {
                        currentDocScale = 1.0;
                        currentPanX = 0;
                        currentPanY = 0;
                    }
                    updateDocZoomTransform();
                });
            }

            // Mouse drag to pan
            stage.addEventListener('mousedown', function(e) {
                if (e.button !== 0) return;
                if (e.target.tagName === 'BUTTON' || e.target.closest('button') || e.target.tagName === 'A') return;
                isDocPanning = true;
                panStartX = e.clientX - currentPanX;
                panStartY = e.clientY - currentPanY;
                stage.classList.add('panning');
            });

            window.addEventListener('mousemove', function(e) {
                if (!isDocPanning) return;
                currentPanX = e.clientX - panStartX;
                currentPanY = e.clientY - panStartY;
                updateDocZoomTransform();
            });

            window.addEventListener('mouseup', function() {
                if (isDocPanning) {
                    isDocPanning = false;
                    if (stage) stage.classList.remove('panning');
                }
            });

            // Keyboard shortcuts
            window.addEventListener('keydown', function(e) {
                var modal = document.getElementById('serveasyDocZoomModal');
                if (!modal || (!modal.classList.contains('active') && modal.style.display !== 'flex')) return;
                if (e.key === 'Escape') {
                    closeDocZoomModal();
                } else if (e.key === '+' || e.key === '=') {
                    docZoomAction('in');
                } else if (e.key === '-' || e.key === '_') {
                    docZoomAction('out');
                } else if (e.key === 'r' || e.key === 'R') {
                    docZoomAction('rotate');
                } else if (e.key === '0') {
                    docZoomAction('reset');
                }
            });
        }

        $(document).ready(function() {
            attachDocZoomListeners();
        });
</script>


<!-- ServEasy Document Zoom Lightbox Modal -->
<div id="serveasyDocZoomModal" class="doc-zoom-modal" tabindex="-1" role="dialog" aria-hidden="true">
    <div class="doc-zoom-backdrop" onclick="closeDocZoomModal()"></div>
    
    <div class="doc-zoom-container">
        <!-- Top Toolbar Header -->
        <div class="doc-zoom-header">
            <div class="doc-zoom-title-area d-flex align-items-center">
                <span class="doc-zoom-icon mr-2"><i class="fas fa-shield-alt text-emerald"></i></span>
                <span id="docZoomTitle" class="doc-zoom-title font-weight-bold text-white">Document Preview</span>
                <span id="docZoomScaleBadge" class="badge badge-dark ml-3 px-2 py-1" style="font-size:0.75rem; background:rgba(255,255,255,0.15);">100%</span>
                <span id="docZoomResBadge" class="badge badge-info ml-2 px-2 py-1" style="font-size:0.75rem; background:rgba(14,165,233,0.25); border:1px solid rgba(14,165,233,0.4); color:#38bdf8; display:none;"></span>
            </div>
            
            <div class="doc-zoom-actions d-flex align-items-center" style="gap: 8px;">
                <button type="button" class="btn btn-sm btn-zoom-action" title="100% Native Pixel Size (1:1)" onclick="docZoomAction('1to1')">
                    <i class="fas fa-expand-arrows-alt"></i><span class="d-none d-md-inline ml-1">1:1 Size</span>
                </button>
                <button type="button" class="btn btn-sm btn-zoom-action" title="Zoom In (Scroll up or click)" onclick="docZoomAction('in')">
                    <i class="fas fa-search-plus"></i><span class="d-none d-md-inline ml-1">Zoom In</span>
                </button>
                <button type="button" class="btn btn-sm btn-zoom-action" title="Zoom Out (Scroll down)" onclick="docZoomAction('out')">
                    <i class="fas fa-search-minus"></i><span class="d-none d-md-inline ml-1">Zoom Out</span>
                </button>
                <button type="button" class="btn btn-sm btn-zoom-action" title="Rotate 90° Clockwise" onclick="docZoomAction('rotate')">
                    <i class="fas fa-redo"></i><span class="d-none d-md-inline ml-1">Rotate</span>
                </button>
                <button type="button" class="btn btn-sm btn-zoom-action" title="Fit to Screen" onclick="docZoomAction('reset')">
                    <i class="fas fa-sync-alt"></i><span class="d-none d-md-inline ml-1">Fit</span>
                </button>
                <button type="button" id="docZoomDownloadBtn" class="btn btn-sm btn-zoom-action btn-zoom-download" title="Download Document Directly" onclick="triggerDirectDownload()">
                    <i class="fas fa-download"></i><span class="d-none d-md-inline ml-1">Download</span>
                </button>
                <button type="button" class="btn btn-sm btn-zoom-close" title="Close (Esc)" onclick="closeDocZoomModal()">
                    <i class="fas fa-times fa-lg"></i>
                </button>
            </div>
        </div>

        <!-- Main Viewing Stage -->
        <div id="docZoomStage" class="doc-zoom-stage">
            <div id="docZoomContentWrapper" class="doc-zoom-content-wrapper">
                <img id="docZoomImage" src="" alt="Document Zoomed" style="display: none; width: auto !important; height: auto !important; max-width: 90vw; max-height: 80vh; object-fit: contain !important; aspect-ratio: auto !important;" draggable="false" />
                <iframe id="docZoomPdfIframe" src="" style="display: none; width: 90vw; height: 80vh; border: none; border-radius: 8px; background: #fff;"></iframe>
            </div>
        </div>

        <!-- Bottom Status / Hint Bar -->
        <div class="doc-zoom-footer">
            <span><i class="fas fa-mouse mr-1"></i> Scroll to Zoom</span>
            <span class="mx-2">•</span>
            <span><i class="fas fa-hand-paper mr-1"></i> Click & Drag to Pan</span>
            <span class="mx-2">•</span>
            <span>Double-Click to Toggle 2x</span>
            <span class="mx-2">•</span>
            <span>Press <kbd style="background: rgba(255,255,255,0.2); color:#fff; padding:1px 5px; border-radius:3px;">ESC</kbd> to Close</span>
        </div>
    </div>
</div>

</body>

</html>
