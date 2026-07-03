// Register the sumo resolve hook for the current Node process. Use via
//   node --import ./scripts/sumo-loader-register.mjs <script>
import { register } from 'node:module';

register('./sumo-loader.mjs', import.meta.url);
