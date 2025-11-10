import { Router } from 'express';
import { body } from 'express-validator';
import * as ctrl from '../controllers/auth.controller.js';
import { verifyAdmin } from '../middleware/verifyAdmin.js';



const router = Router();

router.get('/health', ctrl.checkHealth);

router.post(
    '/register',
    body('name').isLength({ min: 2 }),
    body('email').isEmail(),
    body('password').isLength({ min: 6 }),
    ctrl.register
);

router.post(
    '/login',
    body('email').isEmail(),
    body('password').notEmpty(),
    ctrl.login
);

router.post('/refresh', ctrl.refresh);
router.post('/logout', ctrl.logout);

router.post('/forgot-password', body('email').isEmail(), ctrl.forgot);
router.get('/reset-password/:token', ctrl.checkResetToken);
router.post('/reset-password', ctrl.resetPassword);
router.delete('/delete-user', ctrl.deleteUser);

router.post('/verify', ctrl.verify);


//ADMIN ROUTES
router.patch('/admin/update', verifyAdmin, ctrl.adminUpdate);
router.delete('/admin/delete-user', verifyAdmin, ctrl.adminDeleteUser);

export default router;
