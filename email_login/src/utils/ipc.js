import { callMain } from '@criptext/electron-better-ipc/renderer';

export const getComputerName = () => callMain('get-computer-name');
export const isWindows = () => callMain('get-isWindows');