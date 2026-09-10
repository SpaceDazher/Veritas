import {NextResponse} from 'next/server';
import {capabilities} from '@/lib/board';
export async function GET(){return NextResponse.json(capabilities);}
