import {
  Entity,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../entities/user.entity';
import { Product } from './product.entity';

@Entity({ name: 'wishlist' })
export class Wishlist {
  @PrimaryGeneratedColumn() // Unique identifier for the wishlist entry. It's auto-generated number.
  id: number;

  @ManyToOne(() => User, (user) => user.id, { nullable: false }) // Each wishlist entry is linked to a user.
  @JoinColumn({ name: 'user_id' })
  user: User;

  @ManyToOne(() => Product, (product) => product.id, { nullable: false }) // Each wishlist entry is linked to a product.
  @JoinColumn({ name: 'product_id' })
  product: Product;

  @CreateDateColumn({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' }) // Auto-set creation timestamp.
  created_at: Date;

  @UpdateDateColumn({
    type: 'timestamp',
    default: () => 'CURRENT_TIMESTAMP',
    onUpdate: 'CURRENT_TIMESTAMP',
  }) // Auto-set update timestamp.
  updated_at: Date;
}
