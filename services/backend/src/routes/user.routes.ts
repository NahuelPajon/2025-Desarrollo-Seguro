import { Router } from 'express';
import routes from '../controllers/authController';

const router = Router();

// POST /auth to create a new user
// This route is typically used for user registration
router.post('/', routes.createUser);

// PUT /auth/:id to update an existing user
// This route is typically used for updating user details
router.put('/:id', routes.updateUser);




router.get('/:id/picture', routes.getPicture);
//router.post('/:id/picture', routes.getUserPicture);
//router.delete('/:id/picture', routes.getUserPicture);


export default router;
