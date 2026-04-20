import { Strategy as LocalStrategy } from 'passport-local';
import { pool } from './config/dbConfig.js';
import bcrypt from 'bcrypt';

function initialize(passport) {

    const authenticateUser = async (correo, password, done) => {
        try {
            const results = await pool.query(
                'SELECT * FROM admin WHERE correo = $1',
                [correo]
            );

            if (results.rows.length === 0) {
                // MEJORA: mismo mensaje genérico para correo y contraseña incorrectos.
                // Si dices "correo no registrado", un atacante sabe qué correos existen.
                return done(null, false, { message: 'Correo o contraseña incorrectos' });
            }

            const user = results.rows[0];
            const isMatch = await bcrypt.compare(password, user.password);

            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Correo o contraseña incorrectos' });
            }

        } catch (err) {
            // CORRECCIÓN: se cambió 'throw err' por 'return done(err)'
            // throw err dentro de un callback crashea el servidor completo;
            // done(err) le pasa el error a Passport para que lo maneje correctamente.
            return done(err);
        }
    };

    passport.use(
        new LocalStrategy(
            {
                usernameField: 'correo',
                passwordField: 'password'
            },
            authenticateUser
        )
    );

    passport.serializeUser((user, done) => done(null, user.id));

    passport.deserializeUser(async (id, done) => {
        try {
            const results = await pool.query(
                'SELECT * FROM admin WHERE id = $1',
                [id]
            );
            return done(null, results.rows[0]);
        } catch (err) {
            return done(err);
        }
    });
}

export { initialize };
